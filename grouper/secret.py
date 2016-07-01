import copy
from datetime import timedelta
from enum import Enum

from grouper.fe.forms import SecretForm
from grouper.group import get_groups_by_user
from grouper.model_soup import Group
from grouper.plugin import get_plugins


class SecretError(Exception):
    """Base exception for all exceptions related to secrets. This should be used
    by plugins when raising secret related exceptions as well.
    """
    pass


class SecretRiskLevel(Enum):
    """Risk levels that secrets can have"""
    low = 1
    medium = 2
    high = 3


class Secret(object):
    """This class is the base interface that Grouper uses for all actions involving secrets.
    All instances where Grouper expects a secret from a plugin MUST return an object that
    implements this entire interface (supersets are of course allowed).
    """

    form = SecretForm

    def __init__(self,
                 name,            # type: str
                 distribution,    # type: List[str]
                 owner,           # type: Group
                 rotate,          # type: timedelta
                 history,         # type: int
                 notes,           # type: str
                 risk_level,      # type: int
                 risk_info,       # type: str
                 uses,            # type: str
                 new=False        # type: boolean
                 ):
        # type: (...) -> Secret
        """Creates a new secret object obviously.

        Args:
            name: The name of the secret.
            distribution: A list of strings describing how this secret should be distributed. The
                plugin is responsible for deciding how to interpret this information.
            owner: The group which owns (and is responsible for) this secret.
            rotate: How long the secret should be valid for before it's rotated.
            history: The number of copies of the secret to retain.
            notes: Miscellaneous information about the secret.
            risk_level: How bad it would be if this secret was disclosed.
            risk_info: Information about why this secret has that level
            uses: Information about where and how this secret is used.
        """
        self.name = name
        self.distribution = distribution
        self.owner = owner
        self.rotate = rotate
        self.history = history
        self.notes = notes
        self.risk_level = risk_level
        self.risk_info = risk_info
        self.uses = uses
        self.new = new

    def commit(self, session):
        # type: (Session) -> None
        """Commits all changes to this object (if any) by passing it to the secret management
        plugins.

        Args:
            session: database session

        Throws:
            SecretError (or subclasses) if something doesn't work
        """
        for plugin in get_plugins():
            plugin.commit_secret(session, self)

    def delete(self, session):
        # type: (Session) -> None
        """Deletes this secret from the secret management plugins. Continued use of this object
        after calling delete is undefined.

        Args:
            session: database session

        Throws:
            SecretError (or subclasses) if something doesn't work
        """
        for plugin in get_plugins():
            plugin.delete_secret(session, self)

    def to_dict(self):
        # type: () -> Dict[str, Any]
        """Converts this secret into a unique JSON-serializable dict.

        Returns:
            A dict sufficient to reconstruct this Secret.
        """
        data = copy.copy(self.__dict__)
        # Convert the non-JSON serializable types to JSON serializable types
        data["rotate"] = data["rotate"].days if data["rotate"] is not None else None
        data["owner"] = data["owner"].name
        return data

    @staticmethod
    def from_dict(session, data):
        # type: (Session, Dict[Str, Any]) -> Secret
        """Takes the dict representation of a Secret (for instance, from to_dict()) and returns
        a Secret with those values.

        Args:
            session: database session
            data: The dict representation of a Secret

        Returns:
            A Secret derived from the dictionary
        """
        # Convert the JSON serializable types back to native non-JSON serializable types
        tmp = Group.get(session, name=data["owner"])
        if not tmp:
            tmp = Group.get(session, data["owner"])
        data["owner"] = tmp
        data["rotate"] = timedelta(days=data["rotate"]) if data["rotate"] is not None else None
        return Secret(**data)

    @staticmethod
    def get_all_secrets(session):
        # type: (Session) -> Dict[str, Secret]
        """Returns a dictionary with every secret that is managed.

        Returns:
            A dictionary keyed by secret names of all secrets
        """
        ret = dict()
        for plugin in get_plugins():
            ret.update(plugin.get_secrets(session))
        return ret

    def get_secrets_form(self, session, user):
        # type: (Session, User) -> SecretForm
        """Returns the SecretForm representation of this secret object.

        The returned value may be a subclass of SecretForm, and is used for
        autofilling forms when editing information about this secret. This
        also properly sets the choices for all select types for when this
        form is validated.

        Args:
            session: database session
            user: the user that is viewing the form

        Returns:
            A SecretForm with fields prefilled by this object's values
        """
        return self.get_secrets_form_generic(session, user, obj=self)

    @classmethod
    def get_secrets_form_args(cls, session, user, args):
        # type: (Session, User, Dict[str, Any]) -> SecretForm
        """Returns a SecretForm filled out with args.

        The returned value may be a subclass of SecretForm, and is used for
        autofilling forms when editing information about this secret. This
        also properly sets the choices for all select types for when this
        form is validated.

        Args:
            session: database session
            user: the user that is viewing the form
            args: the arguments we're filling into the form

        Returns:
            A SecretForm with fields prefilled with the values in args
        """
        return cls.get_secrets_form_generic(session, user, args)

    @classmethod
    def get_secrets_form_generic(cls, session, user, args={}, obj=None):
        # type: (Session, User, Dict[str, Any], Secret) -> SecretForm
        """Returns a SecretForm filled out with either args or obj.

        The returned value may be a subclass of SecretForm, and is used for
        autofilling forms when editing information about this secret. This
        also properly sets the choices for all select types for when this
        form is validated.

        Args:
            session: database session
            user: the user that is viewing the form
            args: the arguments we're filling into the form
            obj: a Secret object whose values are filled into the form

        Returns:
            A SecretForm with fields prefilled by either the object's or arg's values
        """
        if obj:
            # Don't want to modify the object we're given
            obj = copy.copy(obj)
            # The form expects the owner to be an id, not a Group
            obj.owner = obj.owner.id
            # The form expects the distribution to be a single string with newlines
            obj.distribution = "\r\n".join(obj.distribution)
        form = cls.form(args, obj=obj)

        form.owner.choices = [[-1, "(select one)"]]
        for group, group_edge in get_groups_by_user(session, user):
            form.owner.choices.append([int(group.id), group.name])

        form.risk_level.choices = [[-1, "(select one)"]]
        for level in SecretRiskLevel:
            form.risk_level.choices.append([level.value, level.name])

        return form

    @classmethod
    def secret_from_form(cls, session, form, new):
        # type: (Session, SecretForm, bool) -> Secret
        """Returns a Secret (or subclass) derived from the values in the form.

        Args:
            session: database session
            form: the form with the necessary values
            new: whether this is a new Secret

        Returns:
            A Secret filled out with the data in form
        """
        return cls(
            name=form.data["name"],
            distribution=form.data["distribution"].split("\r\n"),
            owner=Group.get(session, pk=form.data["owner"]),
            rotate=form.data["rotate"],
            history=form.data["history"],
            notes=form.data["notes"],
            risk_level=form.data["risk_level"],
            risk_info=form.data["risk_info"],
            uses=form.data["uses"],
            new=new
        )

    def __repr__(self):
        "{}({})".format(self.__name__, self.name)

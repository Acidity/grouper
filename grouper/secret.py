import copy
from datetime import timedelta
from enum import Enum

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

    def __init__(self,
                 name,            # type: str
                 form,            # type: str
                 form_attr,       # type: str
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
            form: The type of the secret. This is called form because type is a python keyword.
            form_attr: Info specific to the form selected
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
        self.form = form
        self.form_attr = form_attr
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
        data["owner"] = data["owner"].id
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
        data["owner"] = Group.get(session, data["owner"])
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

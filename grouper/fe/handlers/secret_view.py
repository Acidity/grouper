from grouper.fe.util import GrouperHandler
from grouper.group import get_groups_by_user
from grouper.secret import Secret, SecretRiskLevel


class SecretView(GrouperHandler):
    def get(self, name=None):
        self.handle_refresh()
        secrets = Secret.get_all_secrets()
        if name not in secrets:
            return self.notfound()

        secret = secrets[name]

        is_owner = secret.owner.name in [group.name for group, group_edge in
            get_groups_by_user(self.session, self.current_user)]

        self.render(
            "secret.html", secret=secret, is_owner=is_owner, risks=SecretRiskLevel
        )

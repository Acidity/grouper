from grouper.fe.handlers.secrets_view import get_secrets_form, secret_from_form
from grouper.fe.util import Alert, form_http_verbs, GrouperHandler
from grouper.group import get_groups_by_user
from grouper.secret import Secret, SecretError, SecretRiskLevel


class SecretView(GrouperHandler):

    def get(self, name=None):
        self.handle_refresh()
        secrets = Secret.get_all_secrets()
        if name not in secrets:
            return self.notfound()

        secret = secrets[name]

        is_owner = secret.owner.name in [group.name for group, group_edge in
            get_groups_by_user(self.session, self.current_user)]

        form = get_secrets_form(self.session, self.current_user, obj=secret)

        self.render(
            "secret.html", secret=secret, is_owner=is_owner, risks=SecretRiskLevel, form=form
        )

    @form_http_verbs
    def post(self, name=None):
        self.handle_refresh()
        secrets = Secret.get_all_secrets()
        if name not in secrets:
            return self.notfound()

        secret = secrets[name]

        is_owner = secret.owner.name in [group.name for group, group_edge in
            get_groups_by_user(self.session, self.current_user)]

        form = get_secrets_form(self.session, self.current_user, self.request.arguments)

        if not form.validate():
            return self.render(
                "secret.html", form=form, secret=secret, alerts=self.get_form_alerts(form.errors),
                is_owner=is_owner, risks=SecretRiskLevel,
            )

        if form.data["name"] != name:
            msg = "You cannot change the name of secrets"
            form.name.errors.append(msg)
            return self.render(
                "secret.html", form=form, secret=secret, alerts=[Alert("danger", msg)],
                is_owner=is_owner, risks=SecretRiskLevel,
            )

        try:
            SecretRiskLevel(form.data["risk_level"])
        except ValueError as e:
            form.risk_level.errors.append(e.message)
            return self.render(
                "secret.html", form=form, secret=secret, alerts=[Alert("danger", e.message)],
                is_owner=is_owner, risks=SecretRiskLevel,
            )

        secret = secret_from_form(self.session, form, new=False)

        try:
            secret.commit()
        except SecretError as e:
            form.name.errors.append(
                e.message
            )
            return self.render(
                "secret.html", form=form, secret=secret, alerts=self.get_form_alerts(form.errors),
                risks=SecretRiskLevel,
            )

        return self.redirect("/secrets/{}?refresh=yes".format(secret.name))

    def delete(self, name=None):
        secrets = Secret.get_all_secrets()
        if name not in secrets:
            return self.notfound()

        secret = secrets[name]

        is_owner = secret.owner.name in [group.name for group, group_edge in
            get_groups_by_user(self.session, self.current_user)]

        form = get_secrets_form(self.session, self.current_user, obj=secret)
        # Apparently if we don't validate the form, the errors are tuples, not lists
        form.validate()

        try:
            secret.delete()
        except SecretError as e:
            form.name.errors.append(
                e.message
            )
            return self.render(
                "secret.html", form=form, secret=secret, alerts=self.get_form_alerts(form.errors),
                risks=SecretRiskLevel, is_owner=is_owner,
            )

        return self.redirect("/secrets")

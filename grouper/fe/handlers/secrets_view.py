from grouper.fe.forms import SecretForm
from grouper.fe.util import Alert, GrouperHandler, paginate_results
from grouper.group import get_groups_by_user
from grouper.model_soup import Group
from grouper.plugin import get_secret_forms
from grouper.secret import Secret, SecretError, SecretRiskLevel


def get_secrets_form(session, user, args={}):
    form = SecretForm(args)
    form.form.choices = [["", "(select one)"]]
    for f in get_secret_forms():
        form.form.choices.append([f, f])

    form.owner.choices = [[-1, "(select one)"]]
    for group, group_edge in get_groups_by_user(session, user):
        form.owner.choices.append([int(group.id), group.name])

    form.risk_level.choices = [[-1, "(select one)"]]
    for level in SecretRiskLevel:
        form.risk_level.choices.append([level.value, level.name])

    return form


def secret_from_form(session, form, new):
    return Secret(
        name=form.data["name"],
        form=form.data["form"],
        form_attr=form.data["form_attr"],
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


class SecretsView(GrouperHandler):

    def get(self):
        self.handle_refresh()
        total, offset, limit, secrets = paginate_results(self, Secret.get_all_secrets().values())

        form = get_secrets_form(self.session, self.current_user, self.request.arguments)

        self.render(
            "secrets.html", secrets=secrets, form=form,
            offset=offset, limit=limit, total=total, risks=SecretRiskLevel,
        )

    def post(self):
        form = get_secrets_form(self.session, self.current_user, self.request.arguments)
        all_secrets = Secret.get_all_secrets()
        total, offset, limit, secrets = paginate_results(self, all_secrets.values())

        if not form.validate():
            return self.render(
                "secrets.html", form=form, secrets=secrets, offset=offset, limit=limit,
                total=total, alerts=self.get_form_alerts(form.errors)
            )

        if form.data["name"] in all_secrets:
            msg = "A secret with the name {} already exists".format(form.data["name"])
            form.name.errors.append(msg)
            return self.render(
                "secrets.html", form=form, secrets=secrets, offset=offset, limit=limit,
                total=total, alerts=[Alert("danger", msg)]
            )

        try:
            SecretRiskLevel(form.data["risk_level"])
        except ValueError as e:
            form.risk_level.errors.append(e.message)
            return self.render(
                "secrets.html", form=form, secrets=secrets, offset=offset, limit=limit,
                total=total, alerts=[Alert("danger", e.message)]
            )

        secret = secret_from_form(self.session, form, new=True)

        try:
            secret.commit()
        except SecretError as e:
            form.name.errors.append(
                e.message
            )
            return self.render(
                "secrets.html", form=form, secrets=secrets, offset=offset, limit=limit,
                total=total, alerts=self.get_form_alerts(form.errors)
            )

        return self.redirect("/secrets/{}?refresh=yes".format(secret.name))

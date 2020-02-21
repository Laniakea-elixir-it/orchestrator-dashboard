from app import db

class Deployments(db.Model):
    uuid = db.Column(db.String(36), primary_key=True)
    creation_time = db.Column(db.DateTime, nullable=True)
    update_time = db.Column(db.DateTime, nullable=True)
    physicalId = db.Column(db.String(36), nullable=True, unique=True)
    description = db.Column(db.String(256), nullable=True)
    status = db.Column(db.String(128), nullable=True)
    status_reason = db.Column(db.String(256), nullable=True)
    outputs = db.Column(db.Text, nullable=True)
    task = db.Column(db.String(64), nullable=True)
    links = db.Column(db.Text, nullable=True)
    sub = db.Column(db.String(36), nullable=True)
    provider_name = db.Column(db.String(128), nullable=True)
    endpoint = db.Column(db.String(256), nullable=True)
    template = db.Column(db.Text, nullable=True)
    inputs = db.Column(db.Text, nullable=True)
    params = db.Column(db.Text, nullable=True)
    locked = db.Column(db.Integer, nullable=True, default='0')
    feedback_required = db.Column(db.Integer, nullable=True, default='1')
    remote = db.Column(db.Integer, nullable=True, default='0')
    issuer = db.Column(db.String(256), nullable=True)
    storage_encryption = db.Column(db.Integer, nullable=True, default='0')
    vault_secret_uuid = db.Column(db.String(36), nullable=True)
    vault_secret_key = db.Column(db.String(36), nullable=True)

    def __repr__(self):
        return '<Deployment {}>'.format(self.uuid)


class Users(db.Model):
   sub = db.Column(db.String(36), primary_key=True)
   name = db.Column(db.String(128), nullable=True)
   username = db.Column(db.String(64), nullable=False)
   given_name = db.Column(db.String(64), nullable=True)
   family_name = db.Column(db.String(64), nullable=True)
   email= db.Column(db.String(64), nullable=False)
   organisation_name = db.Column(db.String(64), nullable=True)
   picture = db.Column(db.String(128), nullable=True)
   role = db.Column(db.String(32), nullable=False, default='user')
   active = db.Column(db.Integer, nullable=True, default='1')

   def __repr__(self):
        return '<User {}>'.format(self.sub) 

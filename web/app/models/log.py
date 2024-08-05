from app import db


class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String, nullable=False)
    level = db.Column(db.String, nullable=False)
    message = db.Column(db.String, nullable=False)
    container_id = db.Column(db.String, nullable=True)

    def __repr__(self):
        return f"Log('{self.timestamp}', '{self.level}', '{self.message}', '{self.container_id}')"

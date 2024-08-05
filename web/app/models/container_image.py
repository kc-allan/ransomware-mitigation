from app import db


class ContainerImage(db.Model):
    __tablename__ = 'container_images'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    image_name = db.Column(db.String(100), nullable=False)
    image_id = db.Column(db.String(255), nullable=False)
    image_tag = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    container_id = db.Column(db.String(64))
    user = db.relationship('User', backref='container_images')

    def __repr__(self):
        return f"ContainerImage('{self.name}', '{self.description}', '{self.image}')"

    def save(self):
        db.session.add(self)
        db.session.commit()

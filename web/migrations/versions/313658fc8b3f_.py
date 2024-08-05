"""empty message

Revision ID: 313658fc8b3f
Revises: 22f1efe9decb
Create Date: 2024-08-04 19:00:48.503123

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '313658fc8b3f'
down_revision = '22f1efe9decb'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('container_images',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('image_name', sa.String(length=100), nullable=False),
    sa.Column('image_id', sa.String(length=255), nullable=False),
    sa.Column('image_tag', sa.String(length=255), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('container_images')
    # ### end Alembic commands ###

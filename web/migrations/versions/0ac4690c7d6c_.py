"""empty message

Revision ID: 0ac4690c7d6c
Revises: b18a314e4962
Create Date: 2024-08-04 20:58:37.188730

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0ac4690c7d6c'
down_revision = 'b18a314e4962'
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
    sa.Column('container_id', sa.String(length=64), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('container_images')
    # ### end Alembic commands ###

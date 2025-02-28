"""FIXING OTP  MODEL

Revision ID: a6de000b658e
Revises: 5a1bf115b63a
Create Date: 2024-10-04 13:48:39.853869

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a6de000b658e'
down_revision = '5a1bf115b63a'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('otps',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('otp_code', sa.String(length=6), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('is_used', sa.Boolean(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('otps')
    # ### end Alembic commands ###

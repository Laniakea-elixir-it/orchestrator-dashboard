"""eleventh_update

Revision ID: cbb45c7afffa
Revises: ef54456ef80c
Create Date: 2026-05-22 15:22:06.582039

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'cbb45c7afffa'
down_revision = 'ef54456ef80c'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('deployments',
        sa.Column('is_behind_vpn', sa.Boolean(), nullable=False, server_default=sa.false())
    )
    op.add_column('deployments',
        sa.Column('is_multi_user', sa.Boolean(), nullable=False, server_default=sa.false())
    )


def downgrade():
    op.drop_column('deployments', 'is_multi_user')
    op.drop_column('deployments', 'is_behind_vpn')

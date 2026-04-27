#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/organizations/manager.py
Organization Manager
Manages organization members, invitations, and roles.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from typing import Any, Optional
from datetime import datetime, timedelta
import uuid
import secrets
import base64
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.base import ABaseAuth
from exonware.xwauth.identity.errors import XWAuthError
from .lifecycle import OrganizationLifecycle
logger = get_logger(__name__)


class OrganizationManager:
    """
    Organization manager for members, invitations, and roles.
    Handles member management, invitations, and role assignments.
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize organization manager.
        Args:
            auth: XWAuth instance
        """
        self._auth = auth
        self._storage = auth.storage
        self._lifecycle = OrganizationLifecycle(auth)
        logger.debug("OrganizationManager initialized")

    async def invite_member(
        self,
        org_id: str,
        email: str,
        role: str = "member",
        inviter_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Invite a member to an organization.
        Args:
            org_id: Organization identifier
            email: Email address of invitee
            role: Role to assign (default: "member")
            inviter_id: User ID of the inviter
        Returns:
            Invitation details with token
        Raises:
            XWAuthError: If organization not found or validation fails
        """
        # Verify organization exists
        org = await self._lifecycle.get_organization(org_id)
        if not org:
            raise XWAuthError(
                f"Organization not found: {org_id}",
                error_code="org_not_found"
            )
        # Validate role
        valid_roles = ["owner", "admin", "member"]
        if role not in valid_roles:
            raise XWAuthError(
                f"Invalid role. Must be one of: {', '.join(valid_roles)}",
                error_code="invalid_role"
            )
        if role == "owner":
            if not inviter_id:
                raise XWAuthError(
                    "Owner invitations require an authenticated inviter",
                    error_code="forbidden_owner_invite",
                )
            inviter_role = await self.get_member_role(org_id, inviter_id)
            if inviter_role != "owner":
                raise XWAuthError(
                    "Only organization owners may invite another owner",
                    error_code="forbidden_owner_invite",
                )
        # Check if user already a member
        user = await self._storage.get_user_by_email(email)
        if user:
            membership = await self._get_membership(org_id, user.id)
            if membership:
                raise XWAuthError(
                    "User is already a member of this organization",
                    error_code="already_member"
                )
        # Generate invitation token
        invitation_token = self._generate_invitation_token()
        # Create invitation
        invitation_data = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "email": email,
            "role": role,
            "inviter_id": inviter_id,
            "token": invitation_token,
            "status": "pending",
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(days=7)).isoformat(),
        }
        # Save invitation
        await self._save_invitation(invitation_data)
        logger.debug(f"Created invitation for {email} to org {org_id}")
        return {
            "invitation_id": invitation_data["id"],
            "email": email,
            "role": role,
            "token": invitation_token,
            "expires_at": invitation_data["expires_at"],
        }

    async def list_members(self, org_id: str) -> list[dict[str, Any]]:
        """
        List all members of an organization.
        Args:
            org_id: Organization identifier
        Returns:
            List of member dictionaries with user info and role
        """
        # Verify organization exists
        org = await self._lifecycle.get_organization(org_id)
        if not org:
            raise XWAuthError(
                f"Organization not found: {org_id}",
                error_code="org_not_found"
            )
        # Get all memberships for this organization
        memberships = await self._get_org_memberships(org_id)
        # Build member list with user details
        members = []
        for membership in memberships:
            user_id = membership.get("user_id")
            if user_id:
                user = await self._storage.get_user(user_id)
                if user:
                    members.append({
                        "user_id": user_id,
                        "email": user.email,
                        "role": membership.get("role", "member"),
                        "joined_at": membership.get("joined_at"),
                    })
        return members

    async def update_member_role(
        self,
        org_id: str,
        user_id: str,
        role: str,
        *,
        actor_user_id: str,
    ) -> dict[str, Any]:
        """
        Update a member's role in an organization.
        Args:
            org_id: Organization identifier
            user_id: User identifier
            role: New role
            actor_user_id: Authenticated user performing the change (delegation / escalation checks)
        Returns:
            Updated membership details
        Raises:
            XWAuthError: If organization or membership not found
        """
        # Validate role
        valid_roles = ["owner", "admin", "member"]
        if role not in valid_roles:
            raise XWAuthError(
                f"Invalid role. Must be one of: {', '.join(valid_roles)}",
                error_code="invalid_role"
            )
        # Verify organization exists
        org = await self._lifecycle.get_organization(org_id)
        if not org:
            raise XWAuthError(
                f"Organization not found: {org_id}",
                error_code="org_not_found"
            )
        actor_role = await self.get_member_role(org_id, actor_user_id)
        if not actor_role or actor_role not in ("owner", "admin"):
            raise XWAuthError(
                "Insufficient permissions to change member roles",
                error_code="forbidden",
            )
        # Get membership
        membership = await self._get_membership(org_id, user_id)
        if not membership:
            raise XWAuthError(
                "User is not a member of this organization",
                error_code="not_member"
            )
        previous = membership.get("role")
        if role == "owner" and actor_role != "owner":
            raise XWAuthError(
                "Only an organization owner may assign the owner role",
                error_code="forbidden_owner_promotion",
            )
        if previous == "owner" and role != "owner":
            if actor_role != "owner":
                raise XWAuthError(
                    "Only an organization owner may remove owner privileges",
                    error_code="forbidden_owner_demotion",
                )
            all_members = await self.list_members(org_id)
            owner_count = sum(1 for m in all_members if m.get("role") == "owner")
            if owner_count <= 1:
                raise XWAuthError(
                    "Cannot demote the last owner of the organization",
                    error_code="last_owner",
                )
        # Update role
        membership["role"] = role
        await self._save_membership(org_id, user_id, membership)
        logger.debug(f"Updated role for user {user_id} in org {org_id} to {role}")
        return {
            "user_id": user_id,
            "org_id": org_id,
            "role": role,
        }

    async def remove_member(
        self,
        org_id: str,
        user_id: str,
    ) -> None:
        """
        Remove a member from an organization.
        Args:
            org_id: Organization identifier
            user_id: User identifier
        Raises:
            XWAuthError: If organization or membership not found
        """
        # Verify organization exists
        org = await self._lifecycle.get_organization(org_id)
        if not org:
            raise XWAuthError(
                f"Organization not found: {org_id}",
                error_code="org_not_found"
            )
        # Get membership
        membership = await self._get_membership(org_id, user_id)
        if not membership:
            raise XWAuthError(
                "User is not a member of this organization",
                error_code="not_member"
            )
        # Prevent removing the last owner
        if membership.get("role") == "owner":
            all_members = await self.list_members(org_id)
            owner_count = sum(1 for m in all_members if m.get("role") == "owner")
            if owner_count <= 1:
                raise XWAuthError(
                    "Cannot remove the last owner of the organization",
                    error_code="last_owner"
                )
        # Delete membership
        await self._delete_membership(org_id, user_id)
        logger.debug(f"Removed user {user_id} from org {org_id}")

    async def get_member_role(self, org_id: str, user_id: str) -> Optional[str]:
        """
        Get a member's role in an organization.
        Args:
            org_id: Organization identifier
            user_id: User identifier
        Returns:
            Role string or None if not a member
        """
        membership = await self._get_membership(org_id, user_id)
        if membership:
            return membership.get("role")
        return None

    def _generate_invitation_token(self) -> str:
        """Generate secure invitation token."""
        random_bytes = secrets.token_bytes(32)
        token = base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')
        return token
    # Storage helper methods

    async def _save_invitation(self, invitation: dict[str, Any]) -> None:
        """Save invitation to storage."""
        invitation_key = f"org_invitation:{invitation['id']}"
        if hasattr(self._storage, 'write'):
            await self._storage.write(invitation_key, invitation)
        else:
            if not hasattr(self._storage, '_org_invitations'):
                self._storage._org_invitations = {}
            self._storage._org_invitations[invitation_key] = invitation

    async def _get_membership(self, org_id: str, user_id: str) -> Optional[dict[str, Any]]:
        """Get membership from storage."""
        membership_key = f"org_member:{org_id}:{user_id}"
        if hasattr(self._storage, 'read'):
            return await self._storage.read(membership_key)
        else:
            if hasattr(self._storage, '_org_memberships'):
                return self._storage._org_memberships.get(membership_key)
        return None

    async def _get_org_memberships(self, org_id: str) -> list[dict[str, Any]]:
        """Get all memberships for an organization."""
        memberships = []
        if hasattr(self._storage, 'read'):
            # Would need to query by org_id (would need indexing in real implementation)
            pass
        else:
            # Fallback: search in-memory storage
            if hasattr(self._storage, '_org_memberships'):
                prefix = f"org_member:{org_id}:"
                for key, membership in self._storage._org_memberships.items():
                    if key.startswith(prefix):
                        memberships.append(membership)
        return memberships

    async def _save_membership(self, org_id: str, user_id: str, membership: dict[str, Any]) -> None:
        """Save membership to storage."""
        membership_key = f"org_member:{org_id}:{user_id}"
        if hasattr(self._storage, 'write'):
            await self._storage.write(membership_key, membership)
        else:
            if not hasattr(self._storage, '_org_memberships'):
                self._storage._org_memberships = {}
            self._storage._org_memberships[membership_key] = membership

    async def _delete_membership(self, org_id: str, user_id: str) -> None:
        """Delete membership from storage."""
        membership_key = f"org_member:{org_id}:{user_id}"
        if hasattr(self._storage, 'delete'):
            await self._storage.delete(membership_key)
        else:
            if hasattr(self._storage, '_org_memberships'):
                self._storage._org_memberships.pop(membership_key, None)

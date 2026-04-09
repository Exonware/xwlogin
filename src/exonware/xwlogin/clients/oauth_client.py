#!/usr/bin/env python3
"""
#exonware/xwlogin/src/exonware/xwlogin/clients/oauth_client.py
OAuth 2.0 Client Manager
Client-side OAuth 2.0 token management for API agents.
Handles token requests, refresh, and credential extraction from configs.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.3
Generation Date: 07-Jan-2025
"""

import os
import requests
from exonware.xwsystem.io.serialization import JsonSerializer
from typing import Any, Optional
from pathlib import Path
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class OAuth2ClientManager:
    """
    Generic OAuth 2.0 client token manager.
    Handles:
    - Extracting oauth_token_pl from configs (supports multiple structures)
    - Requesting tokens using various grant types (password, client_credentials, etc.)
    - Managing token storage and refresh
    - Merging auth credentials into entities
    This is client-side OAuth management (for API agents acting as OAuth clients),
    as opposed to xwauth's server-side OAuth 2.0 server functionality.
    """

    def __init__(self, data_dir: Optional[str] = None):
        """
        Initialize OAuth 2.0 client manager.
        Args:
            data_dir: Base data directory for token storage (optional)
        """
        self.data_dir = data_dir

    def extract_oauth_token_pl_from_config(
        self, 
        auth_config: dict[str, Any], 
        entity_name: str,
        config_structure: str = "auto"
    ) -> Optional[dict[str, Any]]:
        """
        Extract oauth_token_pl from config, handling multiple structures.
        Generic method that works with any config structure:
        - Direct: {"oauth_token_pl": {...}}
        - Nested entities: {"entities": {"ENTITY_NAME": {"oauth_token_pl": {...}}}}
        - Nested agencies: {"agencies": {"AGENCY_NAME": {"oauth_token_pl": {...}}}}
        - Platform-specific: {"platform": {...}}
        Args:
            auth_config: The auth config dictionary
            entity_name: The entity name (used for matching in nested structure)
            config_structure: Structure type ("direct", "nested", "auto" for auto-detect)
        Returns:
            oauth_token_pl dict or None
        """
        # Case 1: Direct oauth_token_pl
        if 'oauth_token_pl' in auth_config:
            return auth_config['oauth_token_pl']
        # Case 2: Nested entities structure
        if 'entities' in auth_config:
            entities_dict = auth_config['entities']
            # Try exact match first
            if entity_name in entities_dict:
                entity_data = entities_dict[entity_name]
                if 'oauth_token_pl' in entity_data:
                    return entity_data['oauth_token_pl']
            # Try normalized match (handle case/hyphen differences)
            normalized_entity_name = self.normalize_entity_name(entity_name)
            for entity_key, entity_data in entities_dict.items():
                if self.normalize_entity_name(entity_key) == normalized_entity_name:
                    if 'oauth_token_pl' in entity_data:
                        return entity_data['oauth_token_pl']
            # If no match, take the first entity (common case: single entity in config)
            if len(entities_dict) == 1:
                first_entity_data = list(entities_dict.values())[0]
                if 'oauth_token_pl' in first_entity_data:
                    return first_entity_data['oauth_token_pl']
        return None

    def normalize_entity_name(self, name: str) -> str:
        """
        Normalize entity name for matching (lowercase, replace hyphens with underscores).
        Args:
            name: Entity name to normalize
        Returns:
            Normalized name
        """
        return name.lower().replace('-', '_').replace(' ', '_')

    def match_entity_key_for_auth_folder(
        self,
        entities: dict[str, dict[str, Any]],
        auth_folder_name: str,
    ) -> str:
        """
        Map xwauth folder name to the entity/agency key in ``entities``
         using the same rules as merge_auth_credentials_into_entities.
        """
        if auth_folder_name in entities:
            return auth_folder_name
        for entity_name in entities.keys():
            if self.normalize_entity_name(entity_name) == self.normalize_entity_name(auth_folder_name):
                return entity_name
        return auth_folder_name

    def request_token(
        self,
        token_url: str,
        oauth_token_pl: dict[str, Any],
        grant_type: Optional[str] = None
    ) -> dict[str, Any]:
        """
        Request OAuth 2.0 token using specified grant type.
        Supports:
        - password (Resource Owner Password Credentials - RFC 6749 Section 4.3)
        - client_credentials (Client Credentials - RFC 6749 Section 4.4)
        - authorization_code (Authorization Code - RFC 6749 Section 4.1)
        Args:
            token_url: OAuth 2.0 token endpoint URL
            oauth_token_pl: OAuth token payload containing credentials
            grant_type: Grant type (defaults to oauth_token_pl.get('grant_type', 'password'))
        Returns:
            Token response dictionary with access_token, token_type, expires_in, etc.
        """
        grant_type = grant_type or oauth_token_pl.get('grant_type', 'password')
        # OAuth 2.0 standard parameters (RFC 6749)
        oauth_params = {
            'grant_type': grant_type,
            'client_id': oauth_token_pl.get('client_id'),
            'client_secret': oauth_token_pl.get('client_secret'),
        }
        # Add grant-specific parameters
        if grant_type == 'password':
            # Resource Owner Password Credentials grant
            if 'username' in oauth_token_pl:
                oauth_params['username'] = oauth_token_pl['username']
            if 'password' in oauth_token_pl:
                oauth_params['password'] = oauth_token_pl['password']
        elif grant_type == 'authorization_code':
            # Authorization Code grant
            if 'code' in oauth_token_pl:
                oauth_params['code'] = oauth_token_pl['code']
            if 'redirect_uri' in oauth_token_pl:
                oauth_params['redirect_uri'] = oauth_token_pl['redirect_uri']
        # Add scope if provided
        if 'scope' in oauth_token_pl:
            oauth_params['scope'] = oauth_token_pl['scope']
        # Make OAuth 2.0 compliant request (RFC 6749 Section 4.3)
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }
        response = requests.post(token_url, data=oauth_params, headers=headers)
        response.raise_for_status()
        return response.json()

    def merge_auth_credentials_into_entities(
        self,
        entities: dict[str, dict[str, Any]],
        platform: str,
        auth_configs: dict[str, dict[str, Any]],
        data_dir: Optional[str] = None
    ) -> None:
        """
        Merge OAuth credentials from xwauth configs into entities.
        Generic method that works with any entity type (agencies, accounts, users, etc.).
        Loads tokens from token.json files if available.
        Args:
            entities: Dictionary of entities (e.g., agencies, accounts)
            platform: Platform name (e.g., 'liveme', 'google')
            auth_configs: Dictionary of auth configs {auth_name: config_dict}
            data_dir: Base data directory for token storage
        """
        if not auth_configs:
            return
        # Merge credentials from configs
        for auth_name, auth_config in auth_configs.items():
            # Extract oauth_token_pl from config
            oauth_token_pl = self.extract_oauth_token_pl_from_config(auth_config, auth_name)
            # Try to match with existing entities (by exact name or normalized name)
            matched_entity_name = None
            for entity_name in entities.keys():
                # Try exact match first
                if entity_name == auth_name:
                    matched_entity_name = entity_name
                    break
                # Try normalized match (handle case/hyphen differences)
                if self.normalize_entity_name(entity_name) == self.normalize_entity_name(auth_name):
                    matched_entity_name = entity_name
                    break
            # If no match found, use auth_name as entity_name
            if matched_entity_name is None:
                matched_entity_name = auth_name
                # Create entity if it doesn't exist
                if matched_entity_name not in entities:
                    entities[matched_entity_name] = {'name': matched_entity_name}
            # Set oauth_token_pl if we found it
            if oauth_token_pl:
                entities[matched_entity_name]['oauth_token_pl'] = oauth_token_pl
        # Load tokens from token.json files if available
        if data_dir:
            self._load_and_merge_tokens(entities, platform, auth_configs, data_dir)

    def _load_and_merge_tokens(
        self,
        entities: dict[str, dict[str, Any]],
        platform: str,
        auth_configs: dict[str, dict[str, Any]],
        data_dir: str
    ) -> None:
        """
        Load tokens from token.json files and merge into entities.
        Args:
            entities: Dictionary of entities
            platform: Platform name
            auth_configs: Dictionary of auth configs
            data_dir: Base data directory
        """
        # Try to load tokens from individual token.json files
        for auth_name in auth_configs.keys():
            entity_key = self.match_entity_key_for_auth_folder(entities, auth_name)
            # Token may live under the config folder (auth_name) or the canonical agency key (entity_key)
            token_paths: list[str] = []
            for folder in (auth_name, entity_key):
                p = os.path.join(data_dir, f"xwauth/{platform}/{folder}/token.json")
                if p not in token_paths:
                    token_paths.append(p)
            for token_file_path in token_paths:
                if not os.path.exists(token_file_path):
                    continue
                try:
                    token_data = JsonSerializer().load_file(token_file_path)
                    request_login = None
                    if "request_login" in token_data:
                        request_login = token_data["request_login"]
                    elif (
                        entity_key in entities
                        and "request_login"
                        in token_data.get("entities", {}).get(entity_key, {})
                    ):
                        request_login = token_data["entities"][entity_key]["request_login"]
                    if request_login and entity_key in entities:
                        self._apply_token_to_entity(entity_key, entities, request_login)
                        break
                except Exception as e:
                    logger.debug(f"Failed to load token from {token_file_path}: {e}")
        # Try standard token.json location
        token_file_path = os.path.join(data_dir, f'xwauth/{platform}/token.json')
        if os.path.exists(token_file_path):
            try:
                token_data = JsonSerializer().load_file(token_file_path)
                if token_data and 'entities' in token_data:
                    for entity_name in entities:
                        if entity_name in token_data['entities']:
                            token_entity = token_data['entities'][entity_name]
                            if 'request_login' in token_entity:
                                self._apply_token_to_entity(entity_name, entities, token_entity['request_login'])
            except Exception as e:
                logger.debug(f"Failed to load tokens from {token_file_path}: {e}")

    def _apply_token_to_entity(
        self,
        entity_name: str,
        entities: dict[str, dict[str, Any]],
        request_login: dict[str, Any]
    ) -> None:
        """
        Apply token data to an entity.
        Args:
            entity_name: Name of the entity
            entities: Dictionary of entities
            request_login: Token response dictionary
        """
        if entity_name not in entities:
            return
        entities[entity_name]['request_login'] = request_login
        # If token is valid, populate headers directly (avoid re-login)
        if (request_login and 
            request_login.get('code') == 200 and 
            request_login.get('message') == 'success' and
            'data' in request_login):
            data = request_login['data']
            # Set headers_authorization and headers_cookie from token
            entities[entity_name]['headers_authorization'] = (
                data.get('token_type', 'Bearer') + ' ' + data.get('access_token', '')
            )
            entities[entity_name]['headers_cookie'] = (
                'uid=' + str(data.get('uid', '')) + '; token=' +
                data.get('token_type', 'Bearer') + '%20' + data.get('access_token', '')
            )
            entities[entity_name]['logged_in'] = True
            # Update entity-specific fields if available
            if 'company_id' in data:
                entities[entity_name]['company_id'] = data['company_id']

#!/usr/bin/env python3
"""
#exonware/xwauth-identity/src/exonware/xwauth/identity/clients/oauth_client.py
OAuth 2.0 client token manager for agents and multi-entity configs.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
"""

from __future__ import annotations

import os
from typing import Any, Optional

import requests
from exonware.xwsystem import get_logger
from exonware.xwsystem.io.serialization import JsonSerializer

logger = get_logger(__name__)


class OAuth2ClientManager:
    """
    Client-side OAuth 2.0 token management (RFC 6749-style form posts).
    Complements xwauth's authorization-server role; works with any token endpoint.
    """

    def __init__(self, data_dir: Optional[str] = None):
        self.data_dir = data_dir

    def extract_oauth_token_pl_from_config(
        self,
        auth_config: dict[str, Any],
        entity_name: str,
        config_structure: str = "auto",
    ) -> Optional[dict[str, Any]]:
        if "oauth_token_pl" in auth_config:
            return auth_config["oauth_token_pl"]
        if "entities" in auth_config:
            entities_dict = auth_config["entities"]
            if entity_name in entities_dict:
                entity_data = entities_dict[entity_name]
                if "oauth_token_pl" in entity_data:
                    return entity_data["oauth_token_pl"]
            normalized_entity_name = self.normalize_entity_name(entity_name)
            for entity_key, entity_data in entities_dict.items():
                if self.normalize_entity_name(entity_key) == normalized_entity_name:
                    if "oauth_token_pl" in entity_data:
                        return entity_data["oauth_token_pl"]
            if len(entities_dict) == 1:
                first_entity_data = list(entities_dict.values())[0]
                if "oauth_token_pl" in first_entity_data:
                    return first_entity_data["oauth_token_pl"]
        return None

    def normalize_entity_name(self, name: str) -> str:
        return name.lower().replace("-", "_").replace(" ", "_")

    def match_entity_key_for_auth_folder(
        self,
        entities: dict[str, dict[str, Any]],
        auth_folder_name: str,
    ) -> str:
        if auth_folder_name in entities:
            return auth_folder_name
        for entity_name in entities.keys():
            if self.normalize_entity_name(entity_name) == self.normalize_entity_name(
                auth_folder_name
            ):
                return entity_name
        return auth_folder_name

    def request_token(
        self,
        token_url: str,
        oauth_token_pl: dict[str, Any],
        grant_type: Optional[str] = None,
    ) -> dict[str, Any]:
        grant_type = grant_type or oauth_token_pl.get("grant_type", "password")
        oauth_params: dict[str, Any] = {
            "grant_type": grant_type,
            "client_id": oauth_token_pl.get("client_id"),
            "client_secret": oauth_token_pl.get("client_secret"),
        }
        if grant_type == "password":
            if "username" in oauth_token_pl:
                oauth_params["username"] = oauth_token_pl["username"]
            if "password" in oauth_token_pl:
                oauth_params["password"] = oauth_token_pl["password"]
        elif grant_type == "authorization_code":
            if "code" in oauth_token_pl:
                oauth_params["code"] = oauth_token_pl["code"]
            if "redirect_uri" in oauth_token_pl:
                oauth_params["redirect_uri"] = oauth_token_pl["redirect_uri"]
        if "scope" in oauth_token_pl:
            oauth_params["scope"] = oauth_token_pl["scope"]
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        response = requests.post(token_url, data=oauth_params, headers=headers)
        response.raise_for_status()
        return response.json()

    def merge_auth_credentials_into_entities(
        self,
        entities: dict[str, dict[str, Any]],
        platform: str,
        auth_configs: dict[str, dict[str, Any]],
        data_dir: Optional[str] = None,
    ) -> None:
        if not auth_configs:
            return
        for auth_name, auth_config in auth_configs.items():
            oauth_token_pl = self.extract_oauth_token_pl_from_config(
                auth_config, auth_name
            )
            matched_entity_name = None
            for entity_name in entities.keys():
                if entity_name == auth_name:
                    matched_entity_name = entity_name
                    break
                if self.normalize_entity_name(entity_name) == self.normalize_entity_name(
                    auth_name
                ):
                    matched_entity_name = entity_name
                    break
            if matched_entity_name is None:
                matched_entity_name = auth_name
                if matched_entity_name not in entities:
                    entities[matched_entity_name] = {"name": matched_entity_name}
            if oauth_token_pl:
                entities[matched_entity_name]["oauth_token_pl"] = oauth_token_pl
        if data_dir:
            self._load_and_merge_tokens(entities, platform, auth_configs, data_dir)

    def _load_and_merge_tokens(
        self,
        entities: dict[str, dict[str, Any]],
        platform: str,
        auth_configs: dict[str, dict[str, Any]],
        data_dir: str,
    ) -> None:
        for auth_name in auth_configs.keys():
            entity_key = self.match_entity_key_for_auth_folder(entities, auth_name)
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
                        request_login = token_data["entities"][entity_key][
                            "request_login"
                        ]
                    if request_login and entity_key in entities:
                        self._apply_token_to_entity(
                            entity_key, entities, request_login
                        )
                        break
                except Exception as e:
                    logger.debug("Failed to load token from %s: %s", token_file_path, e)
        token_file_path = os.path.join(data_dir, f"xwauth/{platform}/token.json")
        if os.path.exists(token_file_path):
            try:
                token_data = JsonSerializer().load_file(token_file_path)
                if token_data and "entities" in token_data:
                    for entity_name in entities:
                        if entity_name in token_data["entities"]:
                            token_entity = token_data["entities"][entity_name]
                            if "request_login" in token_entity:
                                self._apply_token_to_entity(
                                    entity_name,
                                    entities,
                                    token_entity["request_login"],
                                )
            except Exception as e:
                logger.debug("Failed to load tokens from %s: %s", token_file_path, e)

    def _apply_token_to_entity(
        self,
        entity_name: str,
        entities: dict[str, dict[str, Any]],
        request_login: dict[str, Any],
    ) -> None:
        if entity_name not in entities:
            return
        entities[entity_name]["request_login"] = request_login
        if (
            request_login
            and request_login.get("code") == 200
            and request_login.get("message") == "success"
            and "data" in request_login
        ):
            data = request_login["data"]
            entities[entity_name]["headers_authorization"] = (
                data.get("token_type", "Bearer") + " " + data.get("access_token", "")
            )
            entities[entity_name]["headers_cookie"] = (
                "uid="
                + str(data.get("uid", ""))
                + "; token="
                + data.get("token_type", "Bearer")
                + "%20"
                + data.get("access_token", "")
            )
            entities[entity_name]["logged_in"] = True
            if "company_id" in data:
                entities[entity_name]["company_id"] = data["company_id"]

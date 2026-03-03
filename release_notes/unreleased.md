**Unreleased**

* Added token-based authentication support; AppRole takes priority when both methods are configured
* `vault_token` is no longer a required field; `vault_namespace` is no longer required for AppRole
* Fixed AppRole auth being blocked when namespace was not set (not required for open-source Vault)
* Updated bundled `hvac` wheel from `0.10.1` to `2.4.0`; old wheel lacked `auth.approle` support

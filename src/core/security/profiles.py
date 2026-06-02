from enum import Enum
from typing import Dict, Any, Optional
import json
import os
import logging


class SecurityProfile(Enum):
    STANDARD = "standard"
    ENHANCED = "enhanced"
    PARANOID = "paranoid"


class SecurityProfileManager:
    
    # Default profile configurations
    _PROFILE_CONFIGS = {
        SecurityProfile.STANDARD: {
            "name": "Standard",
            "description": "Basic security with minimal performance impact. "
                          "Suitable for low-risk environments.",
            "features": {
                "side_channel_protection": True,
                "secure_memory_basic": True,
                "secure_memory_advanced": False,
                "auto_lock": False,
                "auto_lock_timeout": 300,  # 5 minutes (not used if auto_lock is False)
                "panic_mode": False,
                "stealth_mode": False,
                "system_tray": True,
                "clipboard_monitoring": True,
                "clipboard_auto_clear": 30,  # 30 seconds
                "audit_logging": True,
                "performance_optimized": True,
            },
            "performance_impact": "low",
            "security_level": "basic",
        },
        SecurityProfile.ENHANCED: {
            "name": "Enhanced",
            "description": "Enhanced security with auto-lock and memory protection. "
                          "Recommended for most users.",
            "features": {
                "side_channel_protection": True,
                "secure_memory_basic": True,
                "secure_memory_advanced": True,
                "auto_lock": True,
                "auto_lock_timeout": 300,  # 5 minutes
                "panic_mode": True,
                "stealth_mode": False,
                "system_tray": True,
                "clipboard_monitoring": True,
                "clipboard_auto_clear": 15,  # 15 seconds
                "audit_logging": True,
                "performance_optimized": True,
            },
            "performance_impact": "medium",
            "security_level": "enhanced",
        },
        SecurityProfile.PARANOID: {
            "name": "Paranoid",
            "description": "Maximum security with all features enabled. "
                          "For high-risk environments and security experts.",
            "features": {
                "side_channel_protection": True,
                "secure_memory_basic": True,
                "secure_memory_advanced": True,
                "auto_lock": True,
                "auto_lock_timeout": 60,  # 1 minute
                "panic_mode": True,
                "stealth_mode": True,
                "system_tray": True,
                "clipboard_monitoring": True,
                "clipboard_auto_clear": 5,  # 5 seconds
                "audit_logging": True,
                "performance_optimized": False,  # Prioritize security over performance
            },
            "performance_impact": "high",
            "security_level": "maximum",
        },
    }
    
    def __init__(self, config_path: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        
        # Set configuration path
        if config_path:
            self._config_path = config_path
        else:
            # Default to user config directory
            import appdirs
            app_name = "cryptosafe"
            app_author = "cryptosafe"
            config_dir = appdirs.user_config_dir(app_name, app_author)
            os.makedirs(config_dir, exist_ok=True)
            self._config_path = os.path.join(config_dir, "security_profile.json")
        
        # Current profile
        self._current_profile: Optional[SecurityProfile] = None
        
        # Custom configurations (user overrides)
        self._custom_configs: Dict[SecurityProfile, Dict[str, Any]] = {}
        
        # Load saved profile
        self._load_profile()
    
    def _load_profile(self) -> None:
        try:
            if os.path.exists(self._config_path):
                with open(self._config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # Load current profile
                profile_name = config.get('current_profile')
                if profile_name:
                    try:
                        self._current_profile = SecurityProfile(profile_name)
                        self.logger.info(f"Loaded profile: {self._current_profile.value}")
                    except ValueError:
                        self.logger.warning(f"Invalid profile in config: {profile_name}")
                        self._current_profile = SecurityProfile.ENHANCED
                else:
                    self._current_profile = SecurityProfile.ENHANCED
                
                # Load custom configurations
                custom_configs = config.get('custom_configs', {})
                for profile_name, custom_config in custom_configs.items():
                    try:
                        profile = SecurityProfile(profile_name)
                        self._custom_configs[profile] = custom_config
                    except ValueError:
                        self.logger.warning(f"Invalid profile in custom configs: {profile_name}")
            
            else:
                # Default to Enhanced profile
                self._current_profile = SecurityProfile.ENHANCED
                self.logger.info(f"Using default profile: {self._current_profile.value}")
                
        except Exception as e:
            self.logger.error(f"Error loading profile: {e}")
            self._current_profile = SecurityProfile.ENHANCED
    
    def _save_profile(self) -> None:
        try:
            config = {
                'current_profile': self._current_profile.value if self._current_profile else None,
                'custom_configs': {
                    profile.value: config
                    for profile, config in self._custom_configs.items()
                }
            }
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(self._config_path), exist_ok=True)
            
            with open(self._config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            
            self.logger.debug(f"Saved profile to: {self._config_path}")
            
        except Exception as e:
            self.logger.error(f"Error saving profile: {e}")
    
    def get_current_profile(self) -> SecurityProfile:
        if self._current_profile is None:
            self._current_profile = SecurityProfile.ENHANCED
        return self._current_profile
    
    def set_profile(self, profile: SecurityProfile) -> None:
        if not isinstance(profile, SecurityProfile):
            raise ValueError(f"Invalid profile: {profile}")
        
        old_profile = self._current_profile
        self._current_profile = profile
        
        self.logger.info(f"Switching security profile: {old_profile} -> {profile}")
        
        # Save to disk
        self._save_profile()
        
        # Apply profile configuration
        self._apply_profile(profile)
    
    def _apply_profile(self, profile: SecurityProfile) -> None:
        config = self.get_profile_config(profile)
        
        self.logger.debug(f"Applying profile configuration: {profile.value}")
        
        # Apply configuration to security components
        # This would typically involve:
        # 1. Configuring ActivityMonitor with auto_lock settings
        # 2. Configuring PanicMode with stealth mode
        # 3. Configuring SecureMemory with advanced features
        # 4. Updating ClipboardService with auto-clear timeout
        
        # For now, we just log what would be configured
        features = config['features']
        self.logger.info(f"Profile features: {features}")
    
    def get_profile_config(self, profile: Optional[SecurityProfile] = None) -> Dict[str, Any]:
        if profile is None:
            profile = self.get_current_profile()
        
        # Start with default configuration
        config = self._PROFILE_CONFIGS[profile].copy()
        
        # Apply custom configurations if any
        if profile in self._custom_configs:
            custom_config = self._custom_configs[profile]
            
            # Merge custom features
            if 'features' in custom_config:
                config['features'].update(custom_config['features'])
            
            # Merge other custom settings
            for key, value in custom_config.items():
                if key != 'features':
                    config[key] = value
        
        return config
    
    def get_feature(self, feature_name: str, profile: Optional[SecurityProfile] = None) -> Any:
        config = self.get_profile_config(profile)
        return config['features'].get(feature_name)
    
    def set_custom_config(self, profile: SecurityProfile, config: Dict[str, Any]) -> None:
        if not isinstance(profile, SecurityProfile):
            raise ValueError(f"Invalid profile: {profile}")
        
        self._custom_configs[profile] = config
        self.logger.info(f"Set custom config for profile: {profile.value}")
        
        # Save to disk
        self._save_profile()
        
        # If this is the current profile, reapply it
        if profile == self._current_profile:
            self._apply_profile(profile)
    
    def reset_custom_config(self, profile: SecurityProfile) -> None:
        if not isinstance(profile, SecurityProfile):
            raise ValueError(f"Invalid profile: {profile}")
        
        if profile in self._custom_configs:
            del self._custom_configs[profile]
            self.logger.info(f"Reset custom config for profile: {profile.value}")
            
            # Save to disk
            self._save_profile()
            
            # If this is the current profile, reapply it
            if profile == self._current_profile:
                self._apply_profile(profile)
    
    def get_available_profiles(self) -> Dict[SecurityProfile, Dict[str, Any]]:
        result = {}
        for profile in SecurityProfile:
            config = self.get_profile_config(profile)
            result[profile] = config
        return result
    
    def get_profile_info(self, profile: SecurityProfile) -> Dict[str, Any]:
        config = self.get_profile_config(profile)
        return {
            'name': config['name'],
            'description': config['description'],
            'performance_impact': config['performance_impact'],
            'security_level': config['security_level'],
        }
    
    def is_feature_enabled(self, feature_name: str, profile: Optional[SecurityProfile] = None) -> bool:
        value = self.get_feature(feature_name, profile)
        return bool(value)
    
    def get_configuration_summary(self) -> Dict[str, Any]:
        profile = self.get_current_profile()
        config = self.get_profile_config(profile)
        
        return {
            'profile': profile.value,
            'profile_name': config['name'],
            'enabled_features': [
                feature for feature, enabled in config['features'].items()
                if enabled
            ],
            'disabled_features': [
                feature for feature, enabled in config['features'].items()
                if not enabled
            ],
            'performance_impact': config['performance_impact'],
            'security_level': config['security_level'],
            'has_custom_config': profile in self._custom_configs,
        }


# Global profile manager instance
_profile_manager: Optional[SecurityProfileManager] = None


def get_profile_manager() -> SecurityProfileManager:
    global _profile_manager
    if _profile_manager is None:
        _profile_manager = SecurityProfileManager()
    return _profile_manager


def get_current_profile() -> SecurityProfile:
    manager = get_profile_manager()
    return manager.get_current_profile()


def set_profile(profile: SecurityProfile) -> None:

    manager = get_profile_manager()
    manager.set_profile(profile)


def is_feature_enabled(feature_name: str) -> bool:
    manager = get_profile_manager()
    return manager.is_feature_enabled(feature_name)


# Test the module
if __name__ == "__main__":
    import logging
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Test SecurityProfileManager
    manager = SecurityProfileManager()
    
    print("Testing Security Profile Manager")
    print("=" * 50)
    
    # Get current profile
    current = manager.get_current_profile()
    print(f"Current profile: {current.value}")
    
    # Get configuration
    config = manager.get_profile_config(current)
    print(f"\nConfiguration for {current.value}:")
    print(f"Name: {config['name']}")
    print(f"Description: {config['description']}")
    print(f"Performance impact: {config['performance_impact']}")
    print(f"Security level: {config['security_level']}")
    
    # Check specific features
    print(f"\nFeature checks:")
    print(f"Auto-lock enabled: {manager.is_feature_enabled('auto_lock')}")
    print(f"Auto-lock timeout: {manager.get_feature('auto_lock_timeout')}s")
    print(f"Panic mode enabled: {manager.is_feature_enabled('panic_mode')}")
    print(f"Stealth mode enabled: {manager.is_feature_enabled('stealth_mode')}")
    
    # Get all profiles
    print(f"\nAvailable profiles:")
    profiles = manager.get_available_profiles()
    for profile, config in profiles.items():
        print(f"  {profile.value}: {config['name']} - {config['description']}")
    
    # Test profile switching
    print(f"\nTesting profile switching...")
    manager.set_profile(SecurityProfile.PARANOID)
    print(f"Switched to: {manager.get_current_profile().value}")
    print(f"Auto-lock timeout: {manager.get_feature('auto_lock_timeout')}s")
    
    # Switch back
    manager.set_profile(SecurityProfile.ENHANCED)
    print(f"Switched back to: {manager.get_current_profile().value}")
    
    # Get configuration summary
    print(f"\nConfiguration summary:")
    summary = manager.get_configuration_summary()
    for key, value in summary.items():
        if isinstance(value, list):
            print(f"  {key}:")
            for item in value:
                print(f"    - {item}")
        else:
            print(f"  {key}: {value}")
    
    print("\nTest complete")
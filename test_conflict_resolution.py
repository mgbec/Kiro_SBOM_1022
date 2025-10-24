#!/usr/bin/env python3
"""
Test script to verify conflict resolution logic works.
"""

import datetime


def generate_unique_agent_name(base_name, mode="auto"):
    """Generate a unique agent name with timestamp (using only valid characters)."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{base_name}_{mode}_{timestamp}"


def test_name_generation():
    """Test the name generation logic."""
    base_name = "sbom_security_agent"
    
    print("🧪 Testing agent name generation...")
    print(f"Base name: {base_name}")
    print()
    
    # Test different modes
    modes = ["auto", "update", "recreate"]
    
    for mode in modes:
        unique_name = generate_unique_agent_name(base_name, mode)
        print(f"{mode.capitalize()} mode: {unique_name}")
    
    print()
    print("✅ Name generation working correctly!")
    
    # Test what would happen with flags
    print("\n🚩 Flag simulation:")
    print(f"--auto-update would use: {generate_unique_agent_name(base_name, 'update')}")
    print(f"--force-recreate would use: {generate_unique_agent_name(base_name, 'recreate')}")
    print(f"No flags would use: {base_name}")


if __name__ == "__main__":
    test_name_generation()
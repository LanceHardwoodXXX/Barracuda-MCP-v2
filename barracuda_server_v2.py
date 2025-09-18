#!/usr/bin/env python3
"""
Barracuda CloudGen Firewall MCP Server v2
Supports both policy-driven and standard rule-based firewalls
"""

import os
import sys
import logging
import asyncio
from typing import Optional, Dict, Any, List
import httpx
from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
import json
from datetime import datetime
from enum import Enum

# Configure logging to stderr for MCP compatibility
logging.basicConfig(
    level=os.getenv('LOG_LEVEL', 'INFO'),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger(__name__)

# Suppress verbose logging from libraries
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

# Server configuration
app = Server("barracuda-cgf-admin-v2")

class FirewallMode(Enum):
    """Firewall operation modes"""
    STANDARD = "standard"  # Direct rule manipulation
    POLICY_DRIVEN = "policy_driven"  # Policy-based management
    UNKNOWN = "unknown"

class BarracudaClient:
    """Enhanced client for Barracuda CloudGen Firewall API v2"""
    
    def __init__(self):
        self.base_url = os.getenv('BARRACUDA_HOST', '').rstrip('/')
        self.token = os.getenv('BARRACUDA_API_TOKEN', '')
        self.mode = FirewallMode.UNKNOWN
        
        self.client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True
        )
        
        if not self.base_url:
            logger.error("Missing BARRACUDA_HOST environment variable")
        else:
            logger.info(f"Configured for: {self.base_url}")
        
        if not self.token:
            logger.warning("No API token configured. Set BARRACUDA_API_TOKEN")
    
    async def detect_firewall_mode(self) -> FirewallMode:
        """Detect if firewall is policy-driven or standard"""
        try:
            # Try to access rules endpoint
            result = await self.make_request(
                "GET", 
                "/rest/config/v1/forwarding-firewall/rules",
                params={"expand": "false", "envelope": "false"}
            )
            
            if result:
                if isinstance(result, dict):
                    # Check for policy-driven error
                    if result.get("code") == 409:
                        self.mode = FirewallMode.POLICY_DRIVEN
                        logger.info("Detected: Policy-driven firewall")
                    elif "rules" in result:
                        self.mode = FirewallMode.STANDARD
                        logger.info("Detected: Standard rule-based firewall")
                    else:
                        self.mode = FirewallMode.UNKNOWN
                elif isinstance(result, list):
                    self.mode = FirewallMode.STANDARD
                    logger.info("Detected: Standard rule-based firewall")
            
            return self.mode
            
        except Exception as e:
            logger.error(f"Could not detect firewall mode: {str(e)}")
            return FirewallMode.UNKNOWN
    
    async def make_request(
        self, 
        method: str, 
        endpoint: str, 
        params: Optional[Dict] = None, 
        data: Optional[Dict] = None
    ) -> Optional[Dict]:
        """Make authenticated request to Barracuda API"""
        
        headers = {
            "Accept": "application/json",
            "X-API-Token": self.token
        }
        
        if method.upper() in ["POST", "PUT", "PATCH"]:
            headers["Content-Type"] = "application/json"
        
        try:
            url = f"{self.base_url}{endpoint}"
            
            if method.upper() == "GET":
                response = await self.client.get(url, headers=headers, params=params)
            elif method.upper() == "POST":
                response = await self.client.post(url, headers=headers, json=data)
            elif method.upper() == "PUT":
                response = await self.client.put(url, headers=headers, json=data)
            elif method.upper() == "DELETE":
                response = await self.client.delete(url, headers=headers)
            else:
                logger.error(f"Unsupported method: {method}")
                return None
            
            if response.status_code == 204:
                return {"message": "Success", "status_code": 204}
            elif 200 <= response.status_code < 300:
                return response.json()
            else:
                error = response.json() if response.text else {"message": f"HTTP {response.status_code}"}
                logger.debug(f"API error response: {error}")
                return {"error": error, "status_code": response.status_code}
                
        except Exception as e:
            logger.error(f"Request error: {str(e)}")
            return {"error": str(e)}
    
    async def close(self):
        await self.client.aclose()

# Global client
barracuda_client = BarracudaClient()

def format_status(state: str) -> str:
    """Format status with emoji"""
    if state == "ok":
        return "✅ OK"
    elif state == "warning":
        return "⚠️ Warning"
    elif state == "error":
        return "❌ Error"
    else:
        return f"❓ {state}"

@app.list_tools()
async def list_tools() -> List[Tool]:
    """List available tools"""
    tools = [
        Tool(
            name="get_system_status",
            description="Get comprehensive system health status",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="detect_firewall_mode",
            description="Detect if firewall is policy-driven or standard rule-based",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="list_services",
            description="List all running services on the firewall",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="list_firewall_rules",
            description="List all configured firewall rules (works on standard mode)",
            inputSchema={
                "type": "object",
                "properties": {
                    "expand": {
                        "type": "boolean",
                        "description": "Expand rule details (default: true)",
                        "default": True
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Limit number of rules returned",
                        "default": 100
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="get_firewall_rule",
            description="Get detailed configuration of a specific firewall rule",
            inputSchema={
                "type": "object",
                "properties": {
                    "rule_name": {
                        "type": "string",
                        "description": "Name of the firewall rule"
                    }
                },
                "required": ["rule_name"]
            }
        ),
        Tool(
            name="list_dynamic_rules",
            description="List dynamic firewall rules",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="create_firewall_rule",
            description="Create a new firewall rule (standard mode only)",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Rule name"
                    },
                    "source": {
                        "type": "string",
                        "description": "Source network/IP or reference"
                    },
                    "destination": {
                        "type": "string",
                        "description": "Destination network/IP or reference"
                    },
                    "service": {
                        "type": "string",
                        "description": "Service reference (e.g., HTTP, HTTPS, Any)"
                    },
                    "action": {
                        "type": "string",
                        "description": "Action (pass/block)",
                        "enum": ["pass", "block"]
                    },
                    "bidirectional": {
                        "type": "boolean",
                        "description": "Make rule bidirectional",
                        "default": False
                    }
                },
                "required": ["name", "source", "destination", "service", "action"]
            }
        ),
        Tool(
            name="delete_firewall_rule",
            description="Delete a firewall rule (standard mode only)",
            inputSchema={
                "type": "object",
                "properties": {
                    "rule_name": {
                        "type": "string",
                        "description": "Name of the rule to delete"
                    }
                },
                "required": ["rule_name"]
            }
        ),
        Tool(
            name="list_network_objects",
            description="List all configured network objects",
            inputSchema={
                "type": "object",
                "properties": {
                    "filter": {
                        "type": "string",
                        "description": "Optional filter string"
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="list_service_objects",
            description="List all configured service objects",
            inputSchema={
                "type": "object",
                "properties": {
                    "filter": {
                        "type": "string",
                        "description": "Optional filter string"
                    }
                },
                "required": []
            }
        )
    ]
    
    return tools

@app.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Handle tool calls"""
    try:
        if name == "get_system_status":
            return await get_system_status()
        elif name == "detect_firewall_mode":
            return await detect_firewall_mode()
        elif name == "list_services":
            return await list_services()
        elif name == "list_firewall_rules":
            expand = arguments.get("expand", True)
            limit = arguments.get("limit", 100)
            return await list_firewall_rules(expand, limit)
        elif name == "get_firewall_rule":
            rule_name = arguments.get("rule_name", "")
            return await get_firewall_rule(rule_name)
        elif name == "list_dynamic_rules":
            return await list_dynamic_rules()
        elif name == "create_firewall_rule":
            return await create_firewall_rule(
                arguments.get("name"),
                arguments.get("source"),
                arguments.get("destination"),
                arguments.get("service"),
                arguments.get("action"),
                arguments.get("bidirectional", False)
            )
        elif name == "delete_firewall_rule":
            rule_name = arguments.get("rule_name", "")
            return await delete_firewall_rule(rule_name)
        elif name == "list_network_objects":
            filter_str = arguments.get("filter", "")
            return await list_network_objects(filter_str)
        elif name == "list_service_objects":
            filter_str = arguments.get("filter", "")
            return await list_service_objects(filter_str)
        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]
            
    except Exception as e:
        logger.error(f"Tool execution error: {str(e)}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]

async def get_system_status() -> List[TextContent]:
    """Get comprehensive system status"""
    try:
        result = await barracuda_client.make_request(
            "GET", 
            "/rest/control/v1/box",
            params={"envelope": "false"}
        )
        
        if result and "error" not in result:
            status_text = "🖥️ **Barracuda CloudGen Firewall System Status**\n"
            status_text += "=" * 50 + "\n\n"
            
            status_text += "📊 **System Health:**\n"
            status_text += f"  • Server State: {format_status(result.get('serverState', 'unknown'))}\n"
            status_text += f"  • Process State: {format_status(result.get('procState', 'unknown'))}\n"
            status_text += f"  • Disk State: {format_status(result.get('diskState', 'unknown'))}\n"
            status_text += f"  • System State: {format_status(result.get('systemState', 'unknown'))}\n"
            status_text += f"  • Network State: {format_status(result.get('netState', 'unknown'))}\n"
            status_text += f"  • License State: {format_status(result.get('licState', 'unknown'))}\n"
            
            status_text += "\n🔔 **Event Status:**\n"
            status_text += f"  • Operative Events: {format_status(result.get('eventOperativeState', 'unknown'))}\n"
            status_text += f"  • Security Events: {format_status(result.get('eventSecurityState', 'unknown'))}\n"
            
            status_text += "\n⚙️ **Features:**\n"
            status_text += f"  • BoxNet Activation Required: {'Yes ⚠️' if result.get('boxnetActivationRequired') else 'No ✅'}\n"
            status_text += f"  • Has BoxNet: {'Yes' if result.get('hasBoxnet') else 'No'}\n"
            status_text += f"  • Has Kernel Module: {'Yes' if result.get('hasKernel') else 'No'}\n"
            
            status_text += f"\n🕐 **Checked at:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            
            return [TextContent(type="text", text=status_text)]
        else:
            return [TextContent(type="text", text="❌ Failed to retrieve system status")]
        
    except Exception as e:
        return [TextContent(type="text", text=f"❌ Error: {str(e)}")]

async def detect_firewall_mode() -> List[TextContent]:
    """Detect and report firewall mode"""
    mode = await barracuda_client.detect_firewall_mode()
    
    text = "🔍 **Firewall Mode Detection**\n"
    text += "=" * 50 + "\n\n"
    
    if mode == FirewallMode.STANDARD:
        text += "✅ **Standard Rule-Based Firewall**\n\n"
        text += "This firewall supports direct rule manipulation.\n\n"
        text += "**Available operations:**\n"
        text += "• Create, modify, and delete firewall rules\n"
        text += "• View and manage individual rules\n"
        text += "• Configure rule priorities and positions\n"
        text += "• Manage network and service objects\n"
    elif mode == FirewallMode.POLICY_DRIVEN:
        text += "🔒 **Policy-Driven Firewall**\n\n"
        text += "This firewall uses centralized policy management.\n\n"
        text += "**Limitations:**\n"
        text += "• Cannot directly manipulate rules via API\n"
        text += "• Rules are managed through Barracuda Control Center\n\n"
        text += "**Available operations:**\n"
        text += "• View system status and health\n"
        text += "• List and manage network objects\n"
        text += "• List and manage service objects\n"
        text += "• Monitor services and events\n"
    else:
        text += "❓ **Unknown Firewall Mode**\n\n"
        text += "Could not determine firewall operation mode.\n"
        text += "Some features may not be available.\n"
    
    return [TextContent(type="text", text=text)]

async def list_firewall_rules(expand: bool = True, limit: int = 100) -> List[TextContent]:
    """List firewall rules (standard mode)"""
    try:
        # First check if we're in the right mode
        if barracuda_client.mode == FirewallMode.UNKNOWN:
            await barracuda_client.detect_firewall_mode()
        
        if barracuda_client.mode == FirewallMode.POLICY_DRIVEN:
            return [TextContent(
                type="text",
                text="⚠️ This firewall is policy-driven. Direct rule access is not available.\n"
                     "Rules must be managed through the Barracuda Control Center."
            )]
        
        # Try to get rules
        params = {
            "expand": str(expand).lower(),
            "envelope": "false"
        }
        if limit:
            params["limit"] = str(limit)
        
        result = await barracuda_client.make_request(
            "GET",
            "/rest/config/v1/forwarding-firewall/rules",
            params=params
        )
        
        if result and "rules" in result:
            rules = result["rules"]
            text = f"🔥 **Firewall Rules ({len(rules)} total)**\n"
            text += "=" * 50 + "\n\n"
            
            for i, rule in enumerate(rules[:limit], 1):
                text += f"**{i}. {rule.get('name', 'Unnamed')}**\n"
                
                # Status indicators
                if rule.get('deactivated'):
                    text += "  🔴 Status: Deactivated\n"
                else:
                    text += "  🟢 Status: Active\n"
                
                if rule.get('dynamic'):
                    text += "  ⚡ Type: Dynamic\n"
                
                # Rule details
                text += f"  • Source: {format_rule_object(rule.get('source'))}\n"
                text += f"  • Destination: {format_rule_object(rule.get('destination'))}\n"
                text += f"  • Service: {format_rule_object(rule.get('service'))}\n"
                text += f"  • Action: {rule.get('action', {}).get('type', 'unknown')}\n"
                
                if rule.get('bidirectional'):
                    text += "  • Direction: ↔️ Bidirectional\n"
                
                if rule.get('comment'):
                    text += f"  • Comment: {rule['comment'][:100]}...\n" if len(rule.get('comment', '')) > 100 else f"  • Comment: {rule['comment']}\n"
                
                text += "\n"
            
            if len(rules) > limit:
                text += f"\n... showing {limit} of {len(rules)} rules"
            
            return [TextContent(type="text", text=text)]
        else:
            return [TextContent(type="text", text="❌ Could not retrieve firewall rules")]
        
    except Exception as e:
        return [TextContent(type="text", text=f"❌ Error: {str(e)}")]

async def get_firewall_rule(rule_name: str) -> List[TextContent]:
    """Get specific firewall rule details"""
    if not rule_name:
        return [TextContent(type="text", text="❌ Rule name is required")]
    
    try:
        # Check mode
        if barracuda_client.mode == FirewallMode.POLICY_DRIVEN:
            return [TextContent(
                type="text",
                text="⚠️ This firewall is policy-driven. Direct rule access is not available."
            )]
        
        # Get all rules and find the specific one
        result = await barracuda_client.make_request(
            "GET",
            "/rest/config/v1/forwarding-firewall/rules",
            params={"expand": "true", "envelope": "false"}
        )
        
        if result and "rules" in result:
            for rule in result["rules"]:
                if rule.get("name") == rule_name:
                    text = f"📋 **Firewall Rule: {rule_name}**\n"
                    text += "=" * 50 + "\n\n"
                    text += json.dumps(rule, indent=2)
                    return [TextContent(type="text", text=text)]
            
            return [TextContent(type="text", text=f"❌ Rule '{rule_name}' not found")]
        else:
            return [TextContent(type="text", text="❌ Could not retrieve rules")]
        
    except Exception as e:
        return [TextContent(type="text", text=f"❌ Error: {str(e)}")]

async def list_dynamic_rules() -> List[TextContent]:
    """List dynamic firewall rules"""
    try:
        result = await barracuda_client.make_request(
            "GET",
            "/rest/firewall/v1/forwarding-firewall/rules/dynamic"
        )
        
        if result and "rules" in result:
            rules = result["rules"]
            text = f"⚡ **Dynamic Firewall Rules ({len(rules)} total)**\n"
            text += "=" * 50 + "\n\n"
            
            if rules:
                for i, rule_name in enumerate(rules, 1):
                    text += f"{i}. {rule_name}\n"
            else:
                text += "No dynamic rules configured.\n"
            
            return [TextContent(type="text", text=text)]
        else:
            return [TextContent(type="text", text="❌ Could not retrieve dynamic rules")]
        
    except Exception as e:
        return [TextContent(type="text", text=f"❌ Error: {str(e)}")]

async def create_firewall_rule(
    name: str,
    source: str,
    destination: str,
    service: str,
    action: str,
    bidirectional: bool = False
) -> List[TextContent]:
    """Create a new firewall rule (standard mode only)"""
    
    if barracuda_client.mode == FirewallMode.POLICY_DRIVEN:
        return [TextContent(
            type="text",
            text="⚠️ Cannot create rules on policy-driven firewall.\n"
                 "Rules must be managed through Barracuda Control Center."
        )]
    
    if not all([name, source, destination, service, action]):
        return [TextContent(
            type="text",
            text="❌ All parameters required: name, source, destination, service, action"
        )]
    
    try:
        # Build rule data structure
        rule_data = {
            "name": name,
            "source": {"references": source},
            "destination": {"references": destination},
            "service": {"references": service},
            "action": {"type": action},
            "bidirectional": bidirectional,
            "deactivated": False,
            "dynamic": False,
            "ipVersion": "IPv4",
            "policies": {
                "application": {
                    "applicationControl": False,
                    "sslInspection": False,
                    "urlFilter": False,
                    "virusScan": False
                },
                "schedule": {"type": "always"},
                "ips": "Default"
            }
        }
        
        result = await barracuda_client.make_request(
            "POST",
            "/rest/config/v1/forwarding-firewall/rules",
            data=rule_data
        )
        
        if result and "error" not in result:
            text = f"✅ Successfully created firewall rule '{name}'\n\n"
            text += f"Configuration:\n"
            text += f"• Source: {source}\n"
            text += f"• Destination: {destination}\n"
            text += f"• Service: {service}\n"
            text += f"• Action: {action}\n"
            text += f"• Bidirectional: {'Yes' if bidirectional else 'No'}"
            return [TextContent(type="text", text=text)]
        else:
            error_msg = result.get("error", "Unknown error") if result else "No response"
            return [TextContent(type="text", text=f"❌ Failed to create rule: {error_msg}")]
        
    except Exception as e:
        return [TextContent(type="text", text=f"❌ Error: {str(e)}")]

async def delete_firewall_rule(rule_name: str) -> List[TextContent]:
    """Delete a firewall rule"""
    
    if barracuda_client.mode == FirewallMode.POLICY_DRIVEN:
        return [TextContent(
            type="text",
            text="⚠️ Cannot delete rules on policy-driven firewall.\n"
                 "Rules must be managed through Barracuda Control Center."
        )]
    
    if not rule_name:
        return [TextContent(type="text", text="❌ Rule name is required")]
    
    try:
        result = await barracuda_client.make_request(
            "DELETE",
            f"/rest/config/v1/forwarding-firewall/rules/{rule_name}"
        )
        
        if result and "error" not in result:
            return [TextContent(type="text", text=f"✅ Successfully deleted rule '{rule_name}'")]
        else:
            error_msg = result.get("error", "Unknown error") if result else "No response"
            return [TextContent(type="text", text=f"❌ Failed to delete rule: {error_msg}")]
        
    except Exception as e:
        return [TextContent(type="text", text=f"❌ Error: {str(e)}")]

async def list_services() -> List[TextContent]:
    """List all services"""
    try:
        result = await barracuda_client.make_request("GET", "/rest/control/v1/box/services")
        
        if result and "services" in result:
            services = result["services"]
            text = f"🔧 **Firewall Services ({len(services)} total)**\n"
            text += "=" * 50 + "\n\n"
            
            core_services = ["boxfw", "control", "restd", "boxconfig"]
            logging_services = ["log", "logwrap", "bsyslog", "psyslog", "event"]
            monitoring_services = ["cstat", "qstat", "bsnmp"]
            dns_services = ["bdns"]
            
            categorized = {
                "🔥 Core Services": [],
                "📝 Logging Services": [],
                "📊 Monitoring Services": [],
                "🌐 DNS Services": [],
                "📦 Other Services": []
            }
            
            for svc in services:
                if svc in core_services:
                    categorized["🔥 Core Services"].append(svc)
                elif svc in logging_services:
                    categorized["📝 Logging Services"].append(svc)
                elif svc in monitoring_services:
                    categorized["📊 Monitoring Services"].append(svc)
                elif svc in dns_services:
                    categorized["🌐 DNS Services"].append(svc)
                else:
                    categorized["📦 Other Services"].append(svc)
            
            for category, svc_list in categorized.items():
                if svc_list:
                    text += f"**{category}:**\n"
                    for svc in svc_list:
                        text += f"  • {svc}\n"
                    text += "\n"
            
            return [TextContent(type="text", text=text)]
        else:
            return [TextContent(type="text", text="❌ Failed to retrieve services")]
        
    except Exception as e:
        return [TextContent(type="text", text=f"❌ Error: {str(e)}")]

async def list_network_objects(filter_str: str = "") -> List[TextContent]:
    """List network objects with optional filtering"""
    try:
        result = await barracuda_client.make_request(
            "GET",
            "/rest/config/v1/forwarding-firewall/objects/networks"
        )
        
        if result and "objects" in result:
            objects = result["objects"]
            
            if filter_str:
                filtered = [obj for obj in objects if filter_str.lower() in obj.lower()]
                objects_to_show = filtered
                title = f"🌐 **Network Objects (filtered: '{filter_str}', {len(filtered)} matches)**"
            else:
                objects_to_show = objects
                title = f"🌐 **Network Objects ({len(objects)} total)**"
            
            text = title + "\n" + "=" * 50 + "\n\n"
            
            # Show objects in a more compact format
            for i, obj in enumerate(objects_to_show[:50], 1):
                text += f"{i:3}. {obj}\n"
            
            if len(objects_to_show) > 50:
                text += f"\n... and {len(objects_to_show) - 50} more"
            
            return [TextContent(type="text", text=text)]
        
        return [TextContent(type="text", text="❌ Failed to retrieve network objects")]
        
    except Exception as e:
        return [TextContent(type="text", text=f"❌ Error: {str(e)}")]

async def list_service_objects(filter_str: str = "") -> List[TextContent]:
    """List service objects with optional filtering"""
    try:
        result = await barracuda_client.make_request(
            "GET",
            "/rest/config/v1/forwarding-firewall/objects/services"
        )
        
        if result and "objects" in result:
            objects = result["objects"]
            
            if filter_str:
                filtered = [obj for obj in objects if filter_str.lower() in obj.lower()]
                objects_to_show = filtered
                title = f"🔌 **Service Objects (filtered: '{filter_str}', {len(filtered)} matches)**"
            else:
                objects_to_show = objects
                title = f"🔌 **Service Objects ({len(objects)} total)**"
            
            text = title + "\n" + "=" * 50 + "\n\n"
            
            for i, obj in enumerate(objects_to_show[:50], 1):
                text += f"{i:3}. {obj}\n"
            
            if len(objects_to_show) > 50:
                text += f"\n... and {len(objects_to_show) - 50} more"
            
            return [TextContent(type="text", text=text)]
        
        return [TextContent(type="text", text="❌ Failed to retrieve service objects")]
        
    except Exception as e:
        return
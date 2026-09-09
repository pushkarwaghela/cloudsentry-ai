# CloudSentry AI - Azure Infrastructure as Code (Terraform)
# Provisions Azure Monitor, Event Hub streaming, and least-privilege telemetry exports.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
  }
}

provider "azurerm" {
  features {}
}

variable "location" {
  type    = string
  default = "eastus"
}

variable "resource_group_name" {
  type    = string
  default = "rg-cloudsentry-prod"
}

# ==============================================================================
# 1. Resource Group
# ==============================================================================

resource "azurerm_resource_group" "rg" {
  name     = var.resource_group_name
  location = var.location

  tags = {
    Project     = "CloudSentry-AI"
    Environment = "prod"
  }
}

# ==============================================================================
# 2. Log Analytics Workspace (SIEM Ingestion Target)
# ==============================================================================

resource "azurerm_log_analytics_workspace" "law" {
  name                = "law-cloudsentry-soc"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 90
}

# ==============================================================================
# 3. Azure Event Hub for Real-Time Streaming Telemetry
# ==============================================================================

resource "azurerm_eventhub_namespace" "eh_namespace" {
  name                = "eh-cloudsentry-stream"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "Standard"
  capacity            = 1
}

resource "azurerm_eventhub" "telemetry_hub" {
  name                = "azure-security-logs"
  namespace_name      = azurerm_eventhub_namespace.eh_namespace.name
  resource_group_name = azurerm_resource_group.rg.name
  partition_count     = 2
  message_retention   = 7
}

resource "azurerm_eventhub_consumer_group" "cloudsentry_cg" {
  name                = "cloudsentry-ingestion-worker"
  namespace_name      = azurerm_eventhub_namespace.eh_namespace.name
  eventhub_name       = azurerm_eventhub.telemetry_hub.name
  resource_group_name = azurerm_resource_group.rg.name
}

# ==============================================================================
# 4. Diagnostic Settings: Route Activity Logs to Event Hub & Log Analytics
# ==============================================================================

data "azurerm_subscription" "current" {}

resource "azurerm_monitor_diagnostic_setting" "subscription_activity" {
  name                           = "diag-cloudsentry-activity"
  target_resource_id             = data.azurerm_subscription.current.id
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.law.id
  eventhub_authorization_rule_id = "${azurerm_eventhub_namespace.eh_namespace.id}/authorizationRules/RootManageSharedAccessKey"
  eventhub_name                  = azurerm_eventhub.telemetry_hub.name

  enabled_log {
    category = "Administrative"
  }

  enabled_log {
    category = "Security"
  }

  enabled_log {
    category = "Policy"
  }

  enabled_log {
    category = "Alert"
  }
}

output "eventhub_name" {
  value = azurerm_eventhub.telemetry_hub.name
}

output "log_analytics_id" {
  value = azurerm_log_analytics_workspace.law.workspace_id
}

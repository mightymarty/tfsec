package database

import (
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	database2 "github.com/mightymarty/tfsec/defsec/pkg/providers/azure/database"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) database2.Database {

	mssqlAdapter := mssqlAdapter{
		alertPolicyIDs:    modules.GetChildResourceIDMapByType("azurerm_mssql_server_security_alert_policy"),
		auditingPolicyIDs: modules.GetChildResourceIDMapByType("azurerm_mssql_server_extended_auditing_policy", "azurerm_mssql_database_extended_auditing_policy"),
		firewallIDs:       modules.GetChildResourceIDMapByType("azurerm_sql_firewall_rule", "azurerm_mssql_firewall_rule"),
	}

	mysqlAdapter := mysqlAdapter{
		firewallIDs: modules.GetChildResourceIDMapByType("azurerm_mysql_firewall_rule"),
	}

	mariaDBAdapter := mariaDBAdapter{
		firewallIDs: modules.GetChildResourceIDMapByType("azurerm_mariadb_firewall_rule"),
	}

	postgresqlAdapter := postgresqlAdapter{
		firewallIDs: modules.GetChildResourceIDMapByType("azurerm_postgresql_firewall_rule"),
	}

	return database2.Database{
		MSSQLServers:      mssqlAdapter.adaptMSSQLServers(modules),
		MariaDBServers:    mariaDBAdapter.adaptMariaDBServers(modules),
		MySQLServers:      mysqlAdapter.adaptMySQLServers(modules),
		PostgreSQLServers: postgresqlAdapter.adaptPostgreSQLServers(modules),
	}
}

type mssqlAdapter struct {
	alertPolicyIDs    terraform2.ResourceIDResolutions
	auditingPolicyIDs terraform2.ResourceIDResolutions
	firewallIDs       terraform2.ResourceIDResolutions
}

type mysqlAdapter struct {
	firewallIDs terraform2.ResourceIDResolutions
}

type mariaDBAdapter struct {
	firewallIDs terraform2.ResourceIDResolutions
}

type postgresqlAdapter struct {
	firewallIDs terraform2.ResourceIDResolutions
}

func (a *mssqlAdapter) adaptMSSQLServers(modules terraform2.Modules) []database2.MSSQLServer {
	var mssqlServers []database2.MSSQLServer
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_sql_server") {
			mssqlServers = append(mssqlServers, a.adaptMSSQLServer(resource, module))
		}
		for _, resource := range module.GetResourcesByType("azurerm_mssql_server") {
			mssqlServers = append(mssqlServers, a.adaptMSSQLServer(resource, module))
		}
	}

	orphanResources := modules.GetResourceByIDs(a.alertPolicyIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := database2.MSSQLServer{
			Metadata: types2.NewUnmanagedMetadata(),
			Server: database2.Server{
				Metadata:                  types2.NewUnmanagedMetadata(),
				EnableSSLEnforcement:      types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
				MinimumTLSVersion:         types2.StringDefault("", types2.NewUnmanagedMetadata()),
				EnablePublicNetworkAccess: types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
				FirewallRules:             nil,
			},
			ExtendedAuditingPolicies: nil,
			SecurityAlertPolicies:    nil,
		}
		for _, policy := range orphanResources {
			orphanage.SecurityAlertPolicies = append(orphanage.SecurityAlertPolicies, adaptMSSQLSecurityAlertPolicy(policy))
		}
		mssqlServers = append(mssqlServers, orphanage)

	}

	orphanResources = modules.GetResourceByIDs(a.auditingPolicyIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := database2.MSSQLServer{
			Metadata: types2.NewUnmanagedMetadata(),
			Server: database2.Server{
				Metadata:                  types2.NewUnmanagedMetadata(),
				EnableSSLEnforcement:      types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
				MinimumTLSVersion:         types2.StringDefault("", types2.NewUnmanagedMetadata()),
				EnablePublicNetworkAccess: types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
				FirewallRules:             nil,
			},
		}
		for _, policy := range orphanResources {
			orphanage.ExtendedAuditingPolicies = append(orphanage.ExtendedAuditingPolicies, adaptMSSQLExtendedAuditingPolicy(policy))
		}
		mssqlServers = append(mssqlServers, orphanage)

	}

	orphanResources = modules.GetResourceByIDs(a.firewallIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := database2.MSSQLServer{
			Metadata: types2.NewUnmanagedMetadata(),
		}
		for _, policy := range orphanResources {
			orphanage.FirewallRules = append(orphanage.FirewallRules, adaptFirewallRule(policy))
		}
		mssqlServers = append(mssqlServers, orphanage)

	}

	return mssqlServers
}
func (a *mysqlAdapter) adaptMySQLServers(modules terraform2.Modules) []database2.MySQLServer {
	var mySQLServers []database2.MySQLServer
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_mysql_server") {
			mySQLServers = append(mySQLServers, a.adaptMySQLServer(resource, module))
		}
	}

	orphanResources := modules.GetResourceByIDs(a.firewallIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := database2.MySQLServer{
			Metadata: types2.NewUnmanagedMetadata(),
			Server: database2.Server{
				Metadata:                  types2.NewUnmanagedMetadata(),
				EnableSSLEnforcement:      types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
				MinimumTLSVersion:         types2.StringDefault("", types2.NewUnmanagedMetadata()),
				EnablePublicNetworkAccess: types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
				FirewallRules:             nil,
			},
		}
		for _, policy := range orphanResources {
			orphanage.FirewallRules = append(orphanage.FirewallRules, adaptFirewallRule(policy))
		}
		mySQLServers = append(mySQLServers, orphanage)

	}

	return mySQLServers
}

func (a *mariaDBAdapter) adaptMariaDBServers(modules terraform2.Modules) []database2.MariaDBServer {
	var mariaDBServers []database2.MariaDBServer
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_mariadb_server") {
			mariaDBServers = append(mariaDBServers, a.adaptMariaDBServer(resource, module))
		}
	}

	orphanResources := modules.GetResourceByIDs(a.firewallIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := database2.MariaDBServer{
			Metadata: types2.NewUnmanagedMetadata(),
			Server: database2.Server{
				Metadata:                  types2.NewUnmanagedMetadata(),
				EnableSSLEnforcement:      types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
				MinimumTLSVersion:         types2.StringDefault("", types2.NewUnmanagedMetadata()),
				EnablePublicNetworkAccess: types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
				FirewallRules:             nil,
			},
		}
		for _, policy := range orphanResources {
			orphanage.FirewallRules = append(orphanage.FirewallRules, adaptFirewallRule(policy))
		}
		mariaDBServers = append(mariaDBServers, orphanage)

	}

	return mariaDBServers
}

func (a *postgresqlAdapter) adaptPostgreSQLServers(modules terraform2.Modules) []database2.PostgreSQLServer {
	var postgreSQLServers []database2.PostgreSQLServer
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_postgresql_server") {
			postgreSQLServers = append(postgreSQLServers, a.adaptPostgreSQLServer(resource, module))
		}
	}

	orphanResources := modules.GetResourceByIDs(a.firewallIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := database2.PostgreSQLServer{
			Metadata: types2.NewUnmanagedMetadata(),
			Server: database2.Server{
				Metadata:                  types2.NewUnmanagedMetadata(),
				EnableSSLEnforcement:      types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
				MinimumTLSVersion:         types2.StringDefault("", types2.NewUnmanagedMetadata()),
				EnablePublicNetworkAccess: types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
				FirewallRules:             nil,
			},
			Config: database2.PostgresSQLConfig{
				Metadata:             types2.NewUnmanagedMetadata(),
				LogCheckpoints:       types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
				ConnectionThrottling: types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
				LogConnections:       types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
			},
		}
		for _, policy := range orphanResources {
			orphanage.FirewallRules = append(orphanage.FirewallRules, adaptFirewallRule(policy))
		}
		postgreSQLServers = append(postgreSQLServers, orphanage)

	}

	return postgreSQLServers
}

func (a *mssqlAdapter) adaptMSSQLServer(resource *terraform2.Block, module *terraform2.Module) database2.MSSQLServer {
	minTLSVersionVal := types2.StringDefault("", resource.GetMetadata())
	publicAccessVal := types2.BoolDefault(true, resource.GetMetadata())
	enableSSLEnforcementVal := types2.BoolDefault(false, resource.GetMetadata())

	var auditingPolicies []database2.ExtendedAuditingPolicy
	var alertPolicies []database2.SecurityAlertPolicy
	var firewallRules []database2.FirewallRule

	if resource.TypeLabel() == "azurerm_mssql_server" {
		minTLSVersionAttr := resource.GetAttribute("minimum_tls_version")
		minTLSVersionVal = minTLSVersionAttr.AsStringValueOrDefault("", resource)

		publicAccessAttr := resource.GetAttribute("public_network_access_enabled")
		publicAccessVal = publicAccessAttr.AsBoolValueOrDefault(true, resource)

	}

	alertPolicyBlocks := module.GetReferencingResources(resource, "azurerm_mssql_server_security_alert_policy", "server_name")
	for _, alertBlock := range alertPolicyBlocks {
		a.alertPolicyIDs.Resolve(alertBlock.ID())
		alertPolicies = append(alertPolicies, adaptMSSQLSecurityAlertPolicy(alertBlock))
	}

	auditingPoliciesBlocks := module.GetReferencingResources(resource, "azurerm_mssql_server_extended_auditing_policy", "server_id")
	if resource.HasChild("extended_auditing_policy") {
		auditingPoliciesBlocks = append(auditingPoliciesBlocks, resource.GetBlocks("extended_auditing_policy")...)
	}

	databasesRes := module.GetReferencingResources(resource, "azurerm_mssql_database", "server_id")
	for _, databaseRes := range databasesRes {
		dbAuditingBlocks := module.GetReferencingResources(databaseRes, "azurerm_mssql_database_extended_auditing_policy", "database_id")
		auditingPoliciesBlocks = append(auditingPoliciesBlocks, dbAuditingBlocks...)
	}

	for _, auditBlock := range auditingPoliciesBlocks {
		a.auditingPolicyIDs.Resolve(auditBlock.ID())
		auditingPolicies = append(auditingPolicies, adaptMSSQLExtendedAuditingPolicy(auditBlock))
	}

	firewallRuleBlocks := module.GetReferencingResources(resource, "azurerm_sql_firewall_rule", "server_name")
	firewallRuleBlocks = append(firewallRuleBlocks, module.GetReferencingResources(resource, "azurerm_mssql_firewall_rule", "server_id")...)
	for _, firewallBlock := range firewallRuleBlocks {
		a.firewallIDs.Resolve(firewallBlock.ID())
		firewallRules = append(firewallRules, adaptFirewallRule(firewallBlock))
	}

	return database2.MSSQLServer{
		Metadata: resource.GetMetadata(),
		Server: database2.Server{
			Metadata:                  resource.GetMetadata(),
			EnableSSLEnforcement:      enableSSLEnforcementVal,
			MinimumTLSVersion:         minTLSVersionVal,
			EnablePublicNetworkAccess: publicAccessVal,
			FirewallRules:             firewallRules,
		},
		ExtendedAuditingPolicies: auditingPolicies,
		SecurityAlertPolicies:    alertPolicies,
	}
}

func (a *mysqlAdapter) adaptMySQLServer(resource *terraform2.Block, module *terraform2.Module) database2.MySQLServer {
	var firewallRules []database2.FirewallRule

	enableSSLEnforcementAttr := resource.GetAttribute("ssl_enforcement_enabled")
	enableSSLEnforcementVal := enableSSLEnforcementAttr.AsBoolValueOrDefault(false, resource)

	minTLSVersionAttr := resource.GetAttribute("ssl_minimal_tls_version_enforced")
	minTLSVersionVal := minTLSVersionAttr.AsStringValueOrDefault("TLSEnforcementDisabled", resource)

	publicAccessAttr := resource.GetAttribute("public_network_access_enabled")
	publicAccessVal := publicAccessAttr.AsBoolValueOrDefault(true, resource)

	firewallRuleBlocks := module.GetReferencingResources(resource, "azurerm_mysql_firewall_rule", "server_name")
	for _, firewallBlock := range firewallRuleBlocks {
		a.firewallIDs.Resolve(firewallBlock.ID())
		firewallRules = append(firewallRules, adaptFirewallRule(firewallBlock))
	}

	return database2.MySQLServer{
		Metadata: resource.GetMetadata(),
		Server: database2.Server{
			Metadata:                  resource.GetMetadata(),
			EnableSSLEnforcement:      enableSSLEnforcementVal,
			MinimumTLSVersion:         minTLSVersionVal,
			EnablePublicNetworkAccess: publicAccessVal,
			FirewallRules:             firewallRules,
		},
	}
}

func (a *mariaDBAdapter) adaptMariaDBServer(resource *terraform2.Block, module *terraform2.Module) database2.MariaDBServer {
	var firewallRules []database2.FirewallRule

	enableSSLEnforcementAttr := resource.GetAttribute("ssl_enforcement_enabled")
	enableSSLEnforcementVal := enableSSLEnforcementAttr.AsBoolValueOrDefault(false, resource)

	publicAccessAttr := resource.GetAttribute("public_network_access_enabled")
	publicAccessVal := publicAccessAttr.AsBoolValueOrDefault(true, resource)

	firewallRuleBlocks := module.GetReferencingResources(resource, "azurerm_mariadb_firewall_rule", "server_name")
	for _, firewallBlock := range firewallRuleBlocks {
		a.firewallIDs.Resolve(firewallBlock.ID())
		firewallRules = append(firewallRules, adaptFirewallRule(firewallBlock))
	}

	return database2.MariaDBServer{
		Metadata: resource.GetMetadata(),
		Server: database2.Server{
			Metadata:                  resource.GetMetadata(),
			EnableSSLEnforcement:      enableSSLEnforcementVal,
			EnablePublicNetworkAccess: publicAccessVal,
			FirewallRules:             firewallRules,
		},
	}
}

func (a *postgresqlAdapter) adaptPostgreSQLServer(resource *terraform2.Block, module *terraform2.Module) database2.PostgreSQLServer {
	var firewallRules []database2.FirewallRule

	enableSSLEnforcementAttr := resource.GetAttribute("ssl_enforcement_enabled")
	enableSSLEnforcementVal := enableSSLEnforcementAttr.AsBoolValueOrDefault(false, resource)

	minTLSVersionAttr := resource.GetAttribute("ssl_minimal_tls_version_enforced")
	minTLSVersionVal := minTLSVersionAttr.AsStringValueOrDefault("TLSEnforcementDisabled", resource)

	publicAccessAttr := resource.GetAttribute("public_network_access_enabled")
	publicAccessVal := publicAccessAttr.AsBoolValueOrDefault(true, resource)

	firewallRuleBlocks := module.GetReferencingResources(resource, "azurerm_postgresql_firewall_rule", "server_name")
	for _, firewallBlock := range firewallRuleBlocks {
		a.firewallIDs.Resolve(firewallBlock.ID())
		firewallRules = append(firewallRules, adaptFirewallRule(firewallBlock))
	}

	configBlocks := module.GetReferencingResources(resource, "azurerm_postgresql_configuration", "server_name")
	config := adaptPostgreSQLConfig(resource, configBlocks)

	return database2.PostgreSQLServer{
		Metadata: resource.GetMetadata(),
		Server: database2.Server{
			Metadata:                  resource.GetMetadata(),
			EnableSSLEnforcement:      enableSSLEnforcementVal,
			MinimumTLSVersion:         minTLSVersionVal,
			EnablePublicNetworkAccess: publicAccessVal,
			FirewallRules:             firewallRules,
		},
		Config: config,
	}
}

func adaptPostgreSQLConfig(resource *terraform2.Block, configBlocks []*terraform2.Block) database2.PostgresSQLConfig {
	config := database2.PostgresSQLConfig{
		Metadata:             resource.GetMetadata(),
		LogCheckpoints:       types2.BoolDefault(false, resource.GetMetadata()),
		ConnectionThrottling: types2.BoolDefault(false, resource.GetMetadata()),
		LogConnections:       types2.BoolDefault(false, resource.GetMetadata()),
	}

	for _, configBlock := range configBlocks {

		nameAttr := configBlock.GetAttribute("name")
		valAttr := configBlock.GetAttribute("value")

		if nameAttr.Equals("log_checkpoints") {
			config.LogCheckpoints = types2.Bool(valAttr.Equals("on"), valAttr.GetMetadata())
		}
		if nameAttr.Equals("connection_throttling") {
			config.ConnectionThrottling = types2.Bool(valAttr.Equals("on"), valAttr.GetMetadata())
		}
		if nameAttr.Equals("log_connections") {
			config.LogConnections = types2.Bool(valAttr.Equals("on"), valAttr.GetMetadata())
		}
	}

	return config
}

func adaptMSSQLSecurityAlertPolicy(resource *terraform2.Block) database2.SecurityAlertPolicy {

	emailAddressesAttr := resource.GetAttribute("email_addresses")
	disabledAlertsAttr := resource.GetAttribute("disabled_alerts")

	emailAccountAdminsAttr := resource.GetAttribute("email_account_admins")
	emailAccountAdminsVal := emailAccountAdminsAttr.AsBoolValueOrDefault(false, resource)

	return database2.SecurityAlertPolicy{
		Metadata:           resource.GetMetadata(),
		EmailAddresses:     emailAddressesAttr.AsStringValues(),
		DisabledAlerts:     disabledAlertsAttr.AsStringValues(),
		EmailAccountAdmins: emailAccountAdminsVal,
	}
}

func adaptFirewallRule(resource *terraform2.Block) database2.FirewallRule {
	startIPAttr := resource.GetAttribute("start_ip_address")
	startIPVal := startIPAttr.AsStringValueOrDefault("", resource)

	endIPAttr := resource.GetAttribute("end_ip_address")
	endIPVal := endIPAttr.AsStringValueOrDefault("", resource)

	return database2.FirewallRule{
		Metadata: resource.GetMetadata(),
		StartIP:  startIPVal,
		EndIP:    endIPVal,
	}
}

func adaptMSSQLExtendedAuditingPolicy(resource *terraform2.Block) database2.ExtendedAuditingPolicy {
	retentionInDaysAttr := resource.GetAttribute("retention_in_days")
	retentionInDaysVal := retentionInDaysAttr.AsIntValueOrDefault(0, resource)

	return database2.ExtendedAuditingPolicy{
		Metadata:        resource.GetMetadata(),
		RetentionInDays: retentionInDaysVal,
	}
}

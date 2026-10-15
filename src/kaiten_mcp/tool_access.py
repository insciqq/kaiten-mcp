"""Read/write classification of every Kaiten MCP tool, published as MCP tool annotations.

Each tool is classified by what its handler sends to Kaiten, not by its name:

- ``READ``: only GET requests, plus the chart endpoints that compute analytics through POST
  without changing Kaiten data.
- ``WRITE``: creates or updates data.
- ``DESTRUCTIVE``: deletes, removes, archives or cancels something: every DELETE request and
  every ``delete``/``remove``/``archive`` tool, including the soft deletes sent as PATCH.

Every registered tool needs an explicit entry; the test suite fails for an unclassified tool.
A tool missing from the table at runtime is still announced as a destructive write.
"""

from enum import Enum

from mcp.types import ToolAnnotations


class ToolAccess(Enum):
    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"


READ = ToolAccess.READ
WRITE = ToolAccess.WRITE
DESTRUCTIVE = ToolAccess.DESTRUCTIVE

TOOL_ACCESS: dict[str, ToolAccess] = {
    # audit_and_analytics
    "kaiten_list_audit_logs": READ,
    "kaiten_get_card_activity": READ,
    "kaiten_get_space_activity": READ,
    "kaiten_get_company_activity": READ,
    "kaiten_get_card_location_history": READ,
    "kaiten_get_all_space_activity": READ,
    "kaiten_list_saved_filters": READ,
    "kaiten_create_saved_filter": WRITE,
    "kaiten_get_saved_filter": READ,
    "kaiten_update_saved_filter": WRITE,
    "kaiten_delete_saved_filter": DESTRUCTIVE,
    # automations
    "kaiten_list_automations": READ,
    "kaiten_create_automation": WRITE,
    "kaiten_get_automation": READ,
    "kaiten_update_automation": WRITE,
    "kaiten_delete_automation": DESTRUCTIVE,
    "kaiten_copy_automation": WRITE,
    "kaiten_list_workflows": READ,
    "kaiten_create_workflow": WRITE,
    "kaiten_get_workflow": READ,
    "kaiten_update_workflow": WRITE,
    "kaiten_delete_workflow": DESTRUCTIVE,
    # blockers
    "kaiten_list_card_blockers": READ,
    "kaiten_create_card_blocker": WRITE,
    "kaiten_get_card_blocker": READ,
    "kaiten_update_card_blocker": WRITE,
    "kaiten_delete_card_blocker": DESTRUCTIVE,
    # boards
    "kaiten_list_boards": READ,
    "kaiten_get_board": READ,
    "kaiten_create_board": WRITE,
    "kaiten_update_board": WRITE,
    "kaiten_delete_board": DESTRUCTIVE,
    # card_relations
    "kaiten_list_card_children": READ,
    "kaiten_add_card_child": WRITE,
    "kaiten_remove_card_child": DESTRUCTIVE,
    "kaiten_list_card_parents": READ,
    "kaiten_add_card_parent": WRITE,
    "kaiten_remove_card_parent": DESTRUCTIVE,
    "kaiten_add_planned_relation": WRITE,
    "kaiten_update_planned_relation": WRITE,
    "kaiten_remove_planned_relation": DESTRUCTIVE,
    # card_types
    "kaiten_list_card_types": READ,
    "kaiten_get_card_type": READ,
    "kaiten_create_card_type": WRITE,
    "kaiten_update_card_type": WRITE,
    "kaiten_delete_card_type": DESTRUCTIVE,
    # cards
    "kaiten_list_cards": READ,
    "kaiten_get_card": READ,
    "kaiten_create_card": WRITE,
    "kaiten_update_card": WRITE,
    "kaiten_delete_card": DESTRUCTIVE,
    "kaiten_archive_card": DESTRUCTIVE,
    "kaiten_move_card": WRITE,
    "kaiten_list_all_cards": READ,
    # charts
    "kaiten_get_chart_boards": READ,
    "kaiten_chart_summary": READ,
    "kaiten_chart_block_resolution": READ,
    "kaiten_chart_due_dates": READ,
    "kaiten_chart_cfd": READ,
    "kaiten_chart_control": READ,
    "kaiten_chart_spectral": READ,
    "kaiten_chart_lead_time": READ,
    "kaiten_chart_throughput_capacity": READ,
    "kaiten_chart_throughput_demand": READ,
    "kaiten_chart_task_distribution": READ,
    "kaiten_chart_cycle_time": READ,
    "kaiten_chart_sales_funnel": READ,
    "kaiten_get_compute_job": READ,
    "kaiten_cancel_compute_job": DESTRUCTIVE,
    # checklists
    "kaiten_list_checklists": READ,
    "kaiten_create_checklist": WRITE,
    "kaiten_update_checklist": WRITE,
    "kaiten_delete_checklist": DESTRUCTIVE,
    "kaiten_list_checklist_items": READ,
    "kaiten_create_checklist_item": WRITE,
    "kaiten_update_checklist_item": WRITE,
    "kaiten_delete_checklist_item": DESTRUCTIVE,
    # columns
    "kaiten_list_columns": READ,
    "kaiten_create_column": WRITE,
    "kaiten_update_column": WRITE,
    "kaiten_delete_column": DESTRUCTIVE,
    "kaiten_list_subcolumns": READ,
    "kaiten_create_subcolumn": WRITE,
    "kaiten_update_subcolumn": WRITE,
    "kaiten_delete_subcolumn": DESTRUCTIVE,
    # comments
    "kaiten_list_comments": READ,
    "kaiten_create_comment": WRITE,
    "kaiten_update_comment": WRITE,
    "kaiten_delete_comment": DESTRUCTIVE,
    # custom_properties
    "kaiten_list_custom_properties": READ,
    "kaiten_get_custom_property": READ,
    "kaiten_create_custom_property": WRITE,
    "kaiten_update_custom_property": WRITE,
    "kaiten_delete_custom_property": DESTRUCTIVE,
    "kaiten_list_select_values": READ,
    "kaiten_get_select_value": READ,
    "kaiten_create_select_value": WRITE,
    "kaiten_update_select_value": WRITE,
    "kaiten_delete_select_value": DESTRUCTIVE,
    # documents
    "kaiten_list_documents": READ,
    "kaiten_create_document": WRITE,
    "kaiten_get_document": READ,
    "kaiten_update_document": WRITE,
    "kaiten_delete_document": DESTRUCTIVE,
    "kaiten_list_document_groups": READ,
    "kaiten_create_document_group": WRITE,
    "kaiten_get_document_group": READ,
    "kaiten_update_document_group": WRITE,
    "kaiten_delete_document_group": DESTRUCTIVE,
    # external_links
    "kaiten_list_external_links": READ,
    "kaiten_create_external_link": WRITE,
    "kaiten_update_external_link": WRITE,
    "kaiten_delete_external_link": DESTRUCTIVE,
    # files
    "kaiten_list_card_files": READ,
    "kaiten_create_card_file": WRITE,
    "kaiten_update_card_file": WRITE,
    "kaiten_delete_card_file": DESTRUCTIVE,
    # lanes
    "kaiten_list_lanes": READ,
    "kaiten_create_lane": WRITE,
    "kaiten_update_lane": WRITE,
    "kaiten_delete_lane": DESTRUCTIVE,
    # members
    "kaiten_list_card_members": READ,
    "kaiten_add_card_member": WRITE,
    "kaiten_remove_card_member": DESTRUCTIVE,
    "kaiten_list_users": READ,
    "kaiten_get_current_user": READ,
    # projects
    "kaiten_list_projects": READ,
    "kaiten_create_project": WRITE,
    "kaiten_get_project": READ,
    "kaiten_update_project": WRITE,
    "kaiten_delete_project": DESTRUCTIVE,
    "kaiten_list_project_cards": READ,
    "kaiten_add_project_card": WRITE,
    "kaiten_remove_project_card": DESTRUCTIVE,
    "kaiten_list_sprints": READ,
    "kaiten_create_sprint": WRITE,
    "kaiten_get_sprint": READ,
    "kaiten_update_sprint": WRITE,
    "kaiten_delete_sprint": DESTRUCTIVE,
    # roles_and_groups
    "kaiten_list_space_users": READ,
    "kaiten_add_space_user": WRITE,
    "kaiten_update_space_user": WRITE,
    "kaiten_remove_space_user": DESTRUCTIVE,
    "kaiten_list_company_groups": READ,
    "kaiten_create_company_group": WRITE,
    "kaiten_get_company_group": READ,
    "kaiten_update_company_group": WRITE,
    "kaiten_delete_company_group": DESTRUCTIVE,
    "kaiten_list_group_users": READ,
    "kaiten_add_group_user": WRITE,
    "kaiten_remove_group_user": DESTRUCTIVE,
    "kaiten_list_roles": READ,
    "kaiten_get_role": READ,
    # service_desk
    "kaiten_list_sd_requests": READ,
    "kaiten_create_sd_request": WRITE,
    "kaiten_get_sd_request": READ,
    "kaiten_update_sd_request": WRITE,
    "kaiten_delete_sd_request": DESTRUCTIVE,
    "kaiten_list_sd_services": READ,
    "kaiten_get_sd_service": READ,
    "kaiten_create_sd_service": WRITE,
    "kaiten_update_sd_service": WRITE,
    "kaiten_delete_sd_service": DESTRUCTIVE,
    "kaiten_list_sd_organizations": READ,
    "kaiten_create_sd_organization": WRITE,
    "kaiten_get_sd_organization": READ,
    "kaiten_update_sd_organization": WRITE,
    "kaiten_delete_sd_organization": DESTRUCTIVE,
    "kaiten_list_sd_sla": READ,
    "kaiten_get_sd_sla": READ,
    "kaiten_create_sd_sla": WRITE,
    "kaiten_update_sd_sla": WRITE,
    "kaiten_delete_sd_sla": DESTRUCTIVE,
    "kaiten_list_sd_template_answers": READ,
    "kaiten_get_sd_template_answer": READ,
    "kaiten_create_sd_template_answer": WRITE,
    "kaiten_update_sd_template_answer": WRITE,
    "kaiten_delete_sd_template_answer": DESTRUCTIVE,
    "kaiten_create_sla_rule": WRITE,
    "kaiten_update_sla_rule": WRITE,
    "kaiten_delete_sla_rule": DESTRUCTIVE,
    "kaiten_recalculate_sla": WRITE,
    "kaiten_list_sd_users": READ,
    "kaiten_update_sd_user": WRITE,
    "kaiten_set_sd_user_temp_password": WRITE,
    "kaiten_add_sd_org_user": WRITE,
    "kaiten_update_sd_org_user": WRITE,
    "kaiten_remove_sd_org_user": DESTRUCTIVE,
    "kaiten_batch_add_sd_org_users": WRITE,
    "kaiten_batch_remove_sd_org_users": DESTRUCTIVE,
    "kaiten_get_sd_settings": READ,
    "kaiten_update_sd_settings": WRITE,
    "kaiten_get_sd_stats": READ,
    "kaiten_get_sd_sla_stats": READ,
    "kaiten_add_service_vote_property": WRITE,
    "kaiten_remove_service_vote_property": DESTRUCTIVE,
    "kaiten_attach_card_sla": WRITE,
    "kaiten_detach_card_sla": DESTRUCTIVE,
    "kaiten_get_card_sla_measurements": READ,
    "kaiten_get_space_sla_measurements": READ,
    # spaces
    "kaiten_list_spaces": READ,
    "kaiten_get_space": READ,
    "kaiten_create_space": WRITE,
    "kaiten_update_space": WRITE,
    "kaiten_delete_space": DESTRUCTIVE,
    # subscribers
    "kaiten_list_card_subscribers": READ,
    "kaiten_add_card_subscriber": WRITE,
    "kaiten_remove_card_subscriber": DESTRUCTIVE,
    "kaiten_list_column_subscribers": READ,
    "kaiten_add_column_subscriber": WRITE,
    "kaiten_remove_column_subscriber": DESTRUCTIVE,
    # tags
    "kaiten_list_tags": READ,
    "kaiten_create_tag": WRITE,
    "kaiten_update_tag": WRITE,
    "kaiten_delete_tag": DESTRUCTIVE,
    "kaiten_add_card_tag": WRITE,
    "kaiten_remove_card_tag": DESTRUCTIVE,
    # time_logs
    "kaiten_list_card_time_logs": READ,
    "kaiten_create_time_log": WRITE,
    "kaiten_update_time_log": WRITE,
    "kaiten_delete_time_log": DESTRUCTIVE,
    # tree
    "kaiten_list_children": READ,
    "kaiten_get_tree": READ,
    # utilities
    "kaiten_list_api_keys": READ,
    "kaiten_create_api_key": WRITE,
    "kaiten_delete_api_key": DESTRUCTIVE,
    "kaiten_list_user_timers": READ,
    "kaiten_create_user_timer": WRITE,
    "kaiten_get_user_timer": READ,
    "kaiten_update_user_timer": WRITE,
    "kaiten_delete_user_timer": DESTRUCTIVE,
    "kaiten_list_removed_cards": READ,
    "kaiten_list_removed_boards": READ,
    "kaiten_list_calendars": READ,
    "kaiten_get_calendar": READ,
    "kaiten_get_company": READ,
    "kaiten_update_company": WRITE,
    # webhooks
    "kaiten_list_webhooks": READ,
    "kaiten_create_webhook": WRITE,
    "kaiten_get_webhook": READ,
    "kaiten_update_webhook": WRITE,
    "kaiten_delete_webhook": DESTRUCTIVE,
    "kaiten_list_incoming_webhooks": READ,
    "kaiten_create_incoming_webhook": WRITE,
    "kaiten_update_incoming_webhook": WRITE,
    "kaiten_delete_incoming_webhook": DESTRUCTIVE,
}

_ANNOTATIONS = {
    READ: ToolAnnotations(readOnlyHint=True),
    WRITE: ToolAnnotations(readOnlyHint=False, destructiveHint=False),
    DESTRUCTIVE: ToolAnnotations(readOnlyHint=False, destructiveHint=True),
}


def tool_annotations(name: str) -> ToolAnnotations:
    """Annotations for a tool; an unclassified tool is a destructive write."""
    return _ANNOTATIONS[TOOL_ACCESS.get(name, DESTRUCTIVE)].model_copy()

{
	"policy" : "irods_policy_enqueue_rule",
        "delay_conditions" : "<PLUSET>1s</PLUSET>",
	"payload" : {
	    "policy" : "irods_policy_execute_rule",
            "payload" : {
	        "policy_to_invoke" : "irods_policy_query_processor",
                "lifetime" : "10",
                "parameters" : {
                    "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME like '/tempZone/home/rods%' AND META_DATA_ATTR_NAME = 'irods::access_time' AND META_DATA_ATTR_VALUE < 'IRODS_TOKEN_LIFETIME'",
                    "query_limit" : 10,
                    "query_type" : "general",
                    "number_of_threads" : 4,
                    "policy_to_invoke" : "irods_policy_data_retention"
                 },
	         "configuration" : {
		     "mode" : "remove_all_replicas"
	         }
             }
        }
}
INPUT null
OUTPUT ruleExecOut


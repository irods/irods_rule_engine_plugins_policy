
#include "policy_engine.hpp"
#include "policy_engine_parameter_capture.hpp"
#include "exec_as_user.hpp"
#include "filesystem.hpp"
#include "policy_engine_configuration_manager.hpp"

#include "rsModAVUMetadata.hpp"
#include "rsOpenCollection.hpp"
#include "rsReadCollection.hpp"
#include "rsCloseCollection.hpp"

namespace {
    int update_access_time_for_data_object(
          rsComm_t*          _comm
        , const std::string& _user_name
        , const std::string& _logical_path
        , const std::string& _attribute) {

        auto ts = std::to_string(std::time(nullptr));
        modAVUMetadataInp_t avuOp{
            "set",
            "-d",
            const_cast<char*>(_logical_path.c_str()),
            const_cast<char*>(_attribute.c_str()),
            const_cast<char*>(ts.c_str()),
            ""};

        auto mod_fcn = [&](auto& comm) {
            return rsModAVUMetadata(&comm, &avuOp);};

        return irods::exec_as_user(*_comm, _user_name, mod_fcn);

    } // update_access_time_for_data_object

    int apply_access_time_to_collection(
          rsComm_t*          _comm
        , const std::string& _user_name
        , int                _handle
        , const std::string& _attribute)
    {
        collEnt_t* coll_ent{nullptr};
        int err = rsReadCollection(_comm, &_handle, &coll_ent);
        while(err >= 0) {
            if(DATA_OBJ_T == coll_ent->objType) {
                using fsp = irods::experimental::filesystem::path;
                auto  lp  = fsp{coll_ent->collName} / fsp{coll_ent->dataName};
                err = update_access_time_for_data_object(_comm, _user_name, lp.string(), _attribute);
            }
            else if(COLL_OBJ_T == coll_ent->objType) {
                collInp_t coll_inp;
                memset(&coll_inp, 0, sizeof(coll_inp));
                rstrcpy(
                    coll_inp.collName,
                    coll_ent->collName,
                    MAX_NAME_LEN);
                int handle = rsOpenCollection(_comm, &coll_inp);
                apply_access_time_to_collection(_comm, _user_name, handle, _attribute);
                rsCloseCollection(_comm, &handle);
            }

            err = rsReadCollection(_comm, &_handle, &coll_ent);

        } // while

        return err;

    } // apply_access_time_to_collection

    namespace pe = irods::policy_engine;

    using json = nlohmann::json;

    irods::error access_time_policy(const pe::context& ctx)
    {

        pe::configuration_manager cfg_mgr{ctx.instance_name, ctx.configuration};

        std::string user_name{}, logical_path{}, source_resource{}, destination_resource{};

        bool collection_operation = false;

        auto [err, attribute] = cfg_mgr.get_value("attribute", "irods::access_time");

        auto cond_input = ctx.parameters.contains("cond_input") ? ctx.parameters.at("cond_input") : json::object();
        collection_operation = !cond_input.empty() && !cond_input[COLLECTION_KW].empty();

        // query processor invocation
        if(ctx.parameters.contains("query_results")) {
            using fsp = irods::experimental::filesystem::path;

            std::string tmp_coll_name{}, tmp_data_name{};

            std::tie(user_name, tmp_coll_name, tmp_data_name) =
                extract_array_parameters<3, std::string>(ctx.parameters.at("query_results"));

            logical_path = (fsp{tmp_coll_name} / fsp{tmp_data_name}).string();
        }
        else {
            // event handler or direct call invocation
            std::tie(user_name, logical_path, source_resource, destination_resource) =
                extract_dataobj_inp_parameters(ctx.parameters, tag_first_resc);
        }

        auto comm = ctx.rei->rsComm;

        if(!collection_operation) {
            int status =  update_access_time_for_data_object(comm, user_name, logical_path, attribute);
            if(status < 0) {
                return ERROR(
                           status,
                           boost::format("failed to update access time for object [%s]")
                           % logical_path);
            }
        }
        else {
            // register a collection
            collInp_t coll_inp;
            memset(&coll_inp, 0, sizeof(coll_inp));
            rstrcpy(
                  coll_inp.collName
                , logical_path.c_str()
                , MAX_NAME_LEN);
            int handle = rsOpenCollection(comm, &coll_inp);
            if(handle < 0) {
                return ERROR(
                           handle,
                           boost::format("failed to open collection [%s]") %
                           logical_path);
            }

            int status = apply_access_time_to_collection(comm, user_name, handle, attribute);
            if(status < 0) {
                return ERROR(
                           status,
                           boost::format("failed to update access time for collection [%s]")
                               % logical_path);
            }
        }

        return SUCCESS();

    } // access_time_policy

} // namespace

const char usage[] = R"(
{
    "id": "file:///var/lib/irods/configuration_schemas/v3/policy_engine_usage.json",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "description": ""
        "input_interfaces": [
            {
                "name" : "event_handler-collection_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "event_handler-data_object_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "event_handler-metadata_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "event_handler-user_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "event_handler-resource_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "direct_invocation",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "query_results"
                "description" : "",
                "json_schema" : ""
            },
        ],
    "output_json_for_validation" : ""
}
)";

extern "C"
pe::plugin_pointer_type plugin_factory(
      const std::string& _plugin_name
    , const std::string&) {
    return pe::make(
                 _plugin_name
               , "irods_policy_access_time"
               , usage
               , access_time_policy);
} // plugin_factory

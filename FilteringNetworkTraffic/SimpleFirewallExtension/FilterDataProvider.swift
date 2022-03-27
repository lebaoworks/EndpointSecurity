/*
See LICENSE folder for this sample’s licensing information.

Abstract:
This file contains the implementation of the NEFilterDataProvider sub-class.
*/

import NetworkExtension
import os.log

/**
    The FilterDataProvider class handles connections that match the installed rules by prompting
    the user to allow or deny the connections.
 */
class FilterDataProvider: NEFilterDataProvider {

    // MARK: Properties

    // MARK: NEFilterDataProvider

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {

        // Filter any directions, protocols, endpoints
        let networkRule = NENetworkRule(remoteNetwork: nil,
                                               remotePrefix: 0,
                                               localNetwork: nil,
                                               localPrefix: 0,
                                               protocol: .any,
                                               direction: .any)
        
        let filterRules =  [NEFilterRule(networkRule: networkRule, action: .filterData)]

        // Allow all flows that do not match the filter rules.
        let filterSettings = NEFilterSettings(rules: filterRules, defaultAction: .allow)

        apply(filterSettings) { error in
            if let applyError = error {
                os_log("Failed to apply filter settings: %@", applyError.localizedDescription)
            }
            completionHandler(error)
        }
    }
    
    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {

        completionHandler()
    }
    
    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        os_log("Got a new flow")

        let d = NSMutableDictionary()
        if flow.url != nil {
            d["Url"] = flow.url?.absoluteString
        }

        let socketFlow = flow as? NEFilterSocketFlow
        if (socketFlow != nil) {
            let remoteEndpoint = socketFlow?.remoteEndpoint as? NWHostEndpoint
            if remoteEndpoint != nil {
                d["remote_address"] = remoteEndpoint?.hostname
                d["remote_port"] = remoteEndpoint?.port
            }
            let localEndpoint = socketFlow?.localEndpoint as? NWHostEndpoint
            if localEndpoint != nil {
                d["local_address"] = localEndpoint?.hostname
                d["local_port"] = localEndpoint?.port
            }
        }
        
        EndpointSecurity.printDict(d)
//        os_log("Got a new flow with local endpoint %{public}@, remote endpoint %{public}@", localEndpoint, remoteEndpoint)
        return .allow()
    }
}

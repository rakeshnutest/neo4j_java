package com.example;

import org.neo4j.procedure.Description;
import org.neo4j.procedure.Name;
import org.neo4j.procedure.UserFunction;
import org.neo4j.graphdb.Node;
import org.neo4j.graphdb.Relationship;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;
import java.util.regex.Pattern;

import org.apache.commons.net.util.SubnetUtils;

/**
 * Provides user-defined functions for Neo4j to evaluate policy rules
 * related to secured resources, VPCs, subnets, interfaces, and VMs.
 */
public class PolicyRuleEvaluator {

    // Regex to detect hostnames (non-IP strings, e.g., example.com, my-service.default.svc.cluster.local)
    private static final Pattern HOSTNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9\\-\\.]*[a-zA-Z0-9]$");

    /**
     * Helper method to check if a string is a hostname.
     */
    private boolean isHostname(String input) {
        if (input == null) return false;
        // Skip if it's a valid IP address
        try {
            InetAddress.getByName(input);
            // If it's an IP, check if it's numeric (IP addresses are not hostnames)
            return !input.matches("^\\d+\\.\\d+\\.\\d+\\.\\d+$") && // IPv4
                   !input.matches("^[0-9a-fA-F:]+$") && // IPv6
                   HOSTNAME_PATTERN.matcher(input).matches();
        } catch (UnknownHostException e) {
            // If parsing fails, it might be a hostname
            return HOSTNAME_PATTERN.matcher(input).matches();
        }
    }

    /**
     * Helper method to safely extract a property as a list of strings.
     */
    private List<String> extractPropertyAsList(Node node, String propertyName) {
        if (node == null || !node.hasProperty(propertyName)) {
            return Collections.emptyList();
        }
        Object property = node.getProperty(propertyName);
        if (property instanceof String[]) {
            return Arrays.asList((String[]) property);
        } else if (property instanceof String) {
            return Collections.singletonList((String) property);
        }
        return Collections.emptyList();
    }

    /**
     * Helper method to safely extract a relationship property as a list of strings.
     */
    private List<String> extractPropertyAsList(Relationship relationship, String propertyName) {
        if (relationship == null || !relationship.hasProperty(propertyName)) {
            return Collections.emptyList();
        }
        Object property = relationship.getProperty(propertyName);
        if (property instanceof String[]) {
            return Arrays.asList((String[]) property);
        } else if (property instanceof String) {
            return Collections.singletonList((String) property);
        }
        return Collections.emptyList();
    }

    /**
     * Helper method to safely extract a property as a string from a relationship.
     */
    private String extractPropertyAsString(Relationship relationship, String propertyName) {
        if (relationship == null || !relationship.hasProperty(propertyName)) {
            return "";
        }
        Object property = relationship.getProperty(propertyName);
        return property != null ? property.toString() : "";
    }

    /**
     * Helper method to safely extract a property as a string.
     */
    private String extractPropertyAsString(Node node, String propertyName) {
        if (node == null || !node.hasProperty(propertyName)) {
            return "";
        }
        Object property = node.getProperty(propertyName);
        return property != null ? property.toString() : "";
    }

    /**
     * Initializes a result map with default values.
     */
    private Map<String, Object> initializeResultMap() {
        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("matches", false);
        resultMap.put("matchType", "none");
        resultMap.put("matchedIps", new ArrayList<String>());
        resultMap.put("unmatchedIps", new ArrayList<String>());
        resultMap.put("exception_matching_ips", new ArrayList<String>());
        resultMap.put("subnetandexceptionNotMatchingIps", new ArrayList<String>());
        resultMap.put("ipv4_address_denied", new ArrayList<String>());
        resultMap.put("ipv6_address_allowed", new ArrayList<String>());
        resultMap.put("ipv6_address_denied", new ArrayList<String>());
        return resultMap;
    }

    /**
     * Checks if an IP address is IPv4.
     */
    private boolean isIPv4(String ip) {
        if (ip == null || isHostname(ip)) return false;
        try {
            InetAddress ipAddress = InetAddress.getByName(ip);
            return ipAddress.getAddress().length == 4;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    /**
     * Checks if an IP address is link-local.
     * IPv4: 169.254.0.0/16
     * IPv6: fe80::/10
     */
    private boolean isLinkLocal(String ip) {
        if (ip == null || isHostname(ip)) return false;
        try {
            InetAddress ipAddress = InetAddress.getByName(ip);
            if (ipAddress.getAddress().length == 4) {
                SubnetUtils utils = new SubnetUtils("169.254.0.0/16");
                utils.setInclusiveHostCount(true);
                return utils.getInfo().isInRange(ip);
            } else {
                String ipStr = ipAddress.getHostAddress().toLowerCase();
                return ipStr.startsWith("fe8") || ipStr.startsWith("fe9") ||
                       ipStr.startsWith("fea") || ipStr.startsWith("feb");
            }
        } catch (UnknownHostException e) {
            return false;
        }
    }

    /**
     * Helper method to filter IPs based on ipv4_only, ipv6_only, is_ipv6_traffic_allowed, and link_local.
     */
    private List<String> filterIpsByProtocol(List<String> ips, boolean ipv4Only, boolean ipv6Only, boolean isIpv6TrafficAllowed, boolean linkLocal) {
        List<String> filteredIps = new ArrayList<>();
        List<String> ipv6Denied = new ArrayList<>();
        for (String ip : ips) {
            if (ip == null || isHostname(ip)) continue;
            boolean isIPv4 = isIPv4(ip);
            boolean isLinkLocalIp = isLinkLocal(ip);
            if (!linkLocal && isLinkLocalIp) continue;
            if (ipv4Only && ipv6Only) {
                filteredIps.add(ip);
            } else if (ipv4Only && !ipv6Only && isIPv4) {
                filteredIps.add(ip);
            } else if (!ipv4Only && ipv6Only && !isIPv4) {
                filteredIps.add(ip);
            } else if (!ipv4Only && !ipv6Only && !isIPv4 && isIpv6TrafficAllowed) {
                filteredIps.add(ip);
            } else if (!ipv6Only && !isIpv6TrafficAllowed && !isIPv4) {
                ipv6Denied.add(ip);
            }
        }
        return filteredIps;
    }

    /**
     * Helper method to filter IPv4 addresses.
     */
    private List<String> filterIpv4Addresses(List<String> ips) {
        List<String> ipv4Addresses = new ArrayList<>();
        for (String ip : ips) {
            if (ip != null && isIPv4(ip)) {
                ipv4Addresses.add(ip);
            }
        }
        return ipv4Addresses;
    }

    /**
     * Helper method to filter IPv6 addresses.
     */
    private List<String> filterIpv6Addresses(List<String> ips) {
        List<String> ipv6Addresses = new ArrayList<>();
        for (String ip : ips) {
            if (ip != null && !isIPv4(ip) && !isHostname(ip)) {
                ipv6Addresses.add(ip);
            }
        }
        return ipv6Addresses;
    }

    /**
     * Helper method to filter IPs for exception matching based on ipv4_only and ipv6_only.
     */
    private List<String> filterExceptionMatches(List<String> ips, List<String> subnetList, List<String> exceptionList, boolean ipv4Only, boolean ipv6Only) {
        List<String> exceptionMatches = new ArrayList<>();
        for (String ip : ips) {
            if (ip == null || isHostname(ip)) continue;
            boolean isIPv4 = isIPv4(ip);
            if ((ipv4Only && !ipv6Only && !isIPv4) || (!ipv4Only && ipv6Only && isIPv4)) {
                continue;
            }
            if (isIpInSubnetList(ip, subnetList) && isIpInSubnetList(ip, exceptionList)) {
                exceptionMatches.add(ip);
            }
        }
        return exceptionMatches;
    }

    /**
     * Computes unmatched IPs as (learnedIps ∪ virtualIps) - matchedIps - ipv6_address_allowed.
     */
    @UserFunction("policy.computeUnmatchedIps")
    @Description("Computes unmatched IPs by taking the union of learned and virtual IPs, then subtracting matched IPs and IPv6 allowed addresses")
    public List<String> computeUnmatchedIps(
            @Name("learnedIps") List<String> learnedIps,
            @Name("virtualIps") List<String> virtualIps,
            @Name("matchedIps") List<String> matchedIps,
            @Name("ipv6_address_allowed") List<String> ipv6AddressAllowed) {
        if (learnedIps == null) learnedIps = Collections.emptyList();
        if (virtualIps == null) virtualIps = Collections.emptyList();
        if (matchedIps == null) matchedIps = Collections.emptyList();
        if (ipv6AddressAllowed == null) ipv6AddressAllowed = Collections.emptyList();

        // Return empty list if any hostname is present
        for (String ip : learnedIps) {
            if (isHostname(ip)) return Collections.emptyList();
        }
        for (String ip : virtualIps) {
            if (isHostname(ip)) return Collections.emptyList();
        }

        Set<String> allIps = new HashSet<>();
        allIps.addAll(learnedIps);
        allIps.addAll(virtualIps);
        allIps.removeAll(matchedIps);
        allIps.removeAll(ipv6AddressAllowed);
        return new ArrayList<>(allIps);
    }
    /**
     * Evaluates if a secured node, VPC, subnet, interface, and VM match based on subnet lists and categories.
     */
    @UserFunction("policy.evaluateSecurityRule")
    @Description("Evaluates security policy rules based on secured, VPC, subnet, interface, VM, host, and cluster properties")
    public Map<String, Object> evaluateSecurityRule(
            @Name("securedNode") Node securedNode,
            @Name("vpcNode") Node vpcNode,
            @Name("subnetNode") Node subnetNode,
            @Name("interfaceRel") Relationship interfaceRel,
            @Name("vmNode") Node vmNode,
            @Name(value = "hostNode", defaultValue = "null") Node hostNode,
            @Name(value = "clusterNode", defaultValue = "null") Node clusterNode) {

        Map<String, Object> resultMap = initializeResultMap();

        if (securedNode == null || vpcNode == null || subnetNode == null || interfaceRel == null || vmNode == null) {
            return Collections.emptyMap();
        }

        String vpcName = extractPropertyAsString(vpcNode, "name");
        String vpcUuid = extractPropertyAsString(vpcNode, "uuid");
        List<String> externalRouterPrefix = extractPropertyAsList(vpcNode, "external_router_prefix");
        String vmName = extractPropertyAsString(vmNode, "name");
        String vmUuid = extractPropertyAsString(vmNode, "uuid");
        List<String> vmCategories = extractPropertyAsList(vmNode, "vm_category_names");
        String subnetName = extractPropertyAsString(subnetNode, "name");
        String subnetUuid = extractPropertyAsString(subnetNode, "uuid");
        String subnetAdvanceNetworking = extractPropertyAsString(subnetNode, "advance_networking");
        List<String> subnetCategories = extractPropertyAsList(subnetNode, "categories");

        resultMap.put("vpc_name", vpcName);
        resultMap.put("vpc_uuid", vpcUuid);
        resultMap.put("external_router_prefix", new ArrayList<>(externalRouterPrefix));
        resultMap.put("vm_name", vmName);
        resultMap.put("vm_uuid", vmUuid);
        resultMap.put("vmCategories", new ArrayList<>(vmCategories));
        resultMap.put("subnet_name", subnetName);
        resultMap.put("subnet_uuid", subnetUuid);
        resultMap.put("subnet_advance_networking", subnetAdvanceNetworking);
        resultMap.put("subnetCategories", new ArrayList<>(subnetCategories));

        // Add host node information if present
        if (hostNode != null) {
            String hostName = extractPropertyAsString(hostNode, "name");
            String hostUuid = extractPropertyAsString(hostNode, "host_uuid");
            String hostIp = extractPropertyAsString(hostNode, "ip_address");
            resultMap.put("host_name", hostName);
            resultMap.put("host_uuid", hostUuid);
            resultMap.put("host_ip", hostIp);
        }

        // Add cluster node information if present
        if (clusterNode != null) {
            String clusterName = extractPropertyAsString(clusterNode, "name");
            String clusterUuid = extractPropertyAsString(clusterNode, "uuid");
            String clusterIp = extractPropertyAsString(clusterNode, "ip_address");
            resultMap.put("cluster_name", clusterName);
            resultMap.put("cluster_uuid", clusterUuid);
            resultMap.put("cluster_ip", clusterIp);
        }

        // Add mac address if present in vmNode
        String macAddress = extractPropertyAsString(interfaceRel, "mac");
        resultMap.put("mac", macAddress);

        String vmPower = extractPropertyAsString(vmNode, "power_state");
        resultMap.put("vmPower", vmPower); 
        // Add hash if present in securedNode
        if (securedNode.hasProperty("hash")) {
            String hash = extractPropertyAsString(securedNode, "hash");
            resultMap.put("hash", hash);
        }

        List<String> learnedIps = extractPropertyAsList(interfaceRel, "learned_ips");
        List<String> virtualIps = extractPropertyAsList(interfaceRel, "VIRTUAL_IPS");
        if (learnedIps.isEmpty() && virtualIps.isEmpty()) {
            resultMap.put("reason", "null matches");
            return resultMap;
        }

        resultMap.put("learnedIps", new ArrayList<>(learnedIps));
        resultMap.put("virtualIps", new ArrayList<>(virtualIps));

        // Check for hostnames in learnedIps
        List<String> allIps = union(learnedIps, virtualIps);
        boolean hasHostname = false;
        for (String ip : allIps) {
            if (isHostname(ip)) {
                hasHostname = true;
                break;
            }
        }

        List<String> securedSubnetCategories = extractPropertyAsList(securedNode, "subnet_category_names");
        List<String> securedVmCategories = extractPropertyAsList(securedNode, "vm_category_names");
        boolean ipv4Only = securedNode.hasProperty("ipv4_only") ? (Boolean) securedNode.getProperty("ipv4_only") : false;
        boolean ipv6Only = securedNode.hasProperty("ipv6_only") ? (Boolean) securedNode.getProperty("ipv6_only") : false;
        boolean isIpv6TrafficAllowed = securedNode.hasProperty("is_ipv6_traffic_allowed") ? (Boolean) securedNode.getProperty("is_ipv6_traffic_allowed") : false;
        boolean linkLocal = securedNode.hasProperty("link_local") ? (Boolean) securedNode.getProperty("link_local") : true;

        // Handle hostname case
        if (hasHostname) {
            resultMap.put("ruleType", "hostname_vm_category");
            if (isSubsetOf(securedVmCategories, vmCategories)) {
                resultMap.put("matches", true);
                resultMap.put("matchType", "vm_category_match");
                List<String> matchedHostnames = new ArrayList<>();
                for (String ip : allIps) {
                    if (isHostname(ip)) {
                        matchedHostnames.add(ip);
                    }
                }
                resultMap.put("matchedIps", matchedHostnames);
                resultMap.put("unmatchedIps", Collections.emptyList());
            } else {
                resultMap.put("reason", "VM categories don't match");
                List<String> unmatchedHostnames = new ArrayList<>();
                for (String ip : allIps) {
                    if (isHostname(ip)) {
                        unmatchedHostnames.add(ip);
                    }
                }
                resultMap.put("unmatchedIps", unmatchedHostnames);
                resultMap.put("matchedIps", Collections.emptyList());
            }
            return resultMap;
        }

        if (securedSubnetCategories.contains("any") && securedVmCategories.contains("any")) {
            resultMap.put("matches", true);
            resultMap.put("matchType", "any_any_match");
            List<String> matchedIps = filterIpsByProtocol(union(learnedIps, virtualIps), ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal);
            resultMap.put("matchedIps", matchedIps);
            resultMap.put("exception_matching_ips", filterExceptionMatches(union(learnedIps, virtualIps),
                extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
            if (!ipv6Only && isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_allowed", filterIpv6Addresses(union(learnedIps, virtualIps)));
            }
            if (!ipv6Only && !isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_denied", filterIpv6Addresses(union(learnedIps, virtualIps)));
            }
            if (!ipv4Only) {
                resultMap.put("ipv4_address_denied", filterIpv4Addresses(union(learnedIps, virtualIps)));
            }
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                matchedIps,
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        List<String> subnetList = extractPropertyAsList(securedNode, "subnet_list");
        if (!subnetList.isEmpty()) {
            List<String> exceptionList = extractPropertyAsList(securedNode, "exception_list");
            resultMap.put("ruleType", "subnet_list");

            Set<String> subnetSet = new HashSet<>(subnetList);
            Set<String> exceptionSet = new HashSet<>(exceptionList);

            List<String> matchedIps = new ArrayList<>();
            List<String> exceptionMatchingIps = new ArrayList<>();
            List<String> subnetandexceptionNotMatchingIps = new ArrayList<>();
            List<String> ipv4Denied = new ArrayList<>();
            List<String> ipv6Allowed = new ArrayList<>();
            List<String> ipv6Denied = new ArrayList<>();

            for (String ip : allIps) {
                if (ip == null) continue;
                boolean isLinkLocalIp = isLinkLocal(ip);
                if (!linkLocal && isLinkLocalIp) continue;
                boolean inSubnetList = isIpInSubnetList(ip, subnetList);
                boolean inExceptionList = isIpInSubnetList(ip, exceptionList);
                boolean isIPv4 = isIPv4(ip);

                boolean includeIp = false;
                if (ipv4Only && ipv6Only) {
                    includeIp = true;
                } else if (ipv4Only && !ipv6Only && isIPv4) {
                    includeIp = true;
                } else if (!ipv4Only && ipv6Only && !isIPv4) {
                    includeIp = true;
                } else if (!ipv4Only && !ipv6Only) {
                    if (!isIPv4 && isIpv6TrafficAllowed) {
                        ipv6Allowed.add(ip);
                        includeIp = true;
                    } else if (!isIPv4 && !isIpv6TrafficAllowed) {
                        ipv6Denied.add(ip);
                    } else if (isIPv4) {
                        ipv4Denied.add(ip);
                    }
                }

                if (inSubnetList && !inExceptionList && includeIp) {
                    matchedIps.add(ip);
                }

                if (inSubnetList && inExceptionList && includeIp) {
                    exceptionMatchingIps.add(ip);
                }

                if (!inSubnetList && !inExceptionList) {
                    subnetandexceptionNotMatchingIps.add(ip);
                }
            }

            resultMap.put("matchedIps", matchedIps);
            resultMap.put("exception_matching_ips", filterExceptionMatches(allIps, subnetList, exceptionList, ipv4Only, ipv6Only));
            resultMap.put("subnetandexceptionNotMatchingIps", subnetandexceptionNotMatchingIps);
            resultMap.put("ipv4_address_denied", ipv4Denied);
            resultMap.put("ipv6_address_allowed", ipv6Allowed);
            resultMap.put("ipv6_address_denied", ipv6Denied);

            if (!matchedIps.isEmpty()) {
                resultMap.put("matches", true);
                resultMap.put("matchType", "ip_subnet_match");
                resultMap.put("matchedWith", "direct_subnet_list");
            } else if (!exceptionMatchingIps.isEmpty()) {
                resultMap.put("matches", true);
                resultMap.put("matchType", "exception_IP_matched");
                resultMap.put("matchedWith", "direct_subnet_list");
            } else {
                resultMap.put("reason", "No IP matches found in subnet list");
            }

            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                matchedIps,
                ipv6Allowed
            ));
            return resultMap;
        }

        List<String> subnetCategoriesFromNode = extractPropertyAsList(subnetNode, "categories");
        List<String> vmCategoriesFromNode = extractPropertyAsList(vmNode, "vm_category_names");

        resultMap.put("securedSubnetCategories", new ArrayList<>(securedSubnetCategories));
        resultMap.put("securedVmCategories", new ArrayList<>(securedVmCategories));
        resultMap.put("actualSubnetCategories", new ArrayList<>(subnetCategoriesFromNode));
        resultMap.put("actualVmCategories", new ArrayList<>(vmCategoriesFromNode));

        boolean hasSubnetCategories = !securedSubnetCategories.isEmpty();
        boolean hasVmCategories = !securedVmCategories.isEmpty();

        if (!hasSubnetCategories && !hasVmCategories) {
            resultMap.put("reason", "All secured node properties are null or empty; no criteria to evaluate");
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        if ((securedSubnetCategories.isEmpty() || securedSubnetCategories.contains("any")) && !securedVmCategories.isEmpty()) {
            resultMap.put("ruleType", "vm_category_only");

            if (isSubsetOf(securedVmCategories, vmCategoriesFromNode)) {
                resultMap.put("matches", true);
                resultMap.put("matchType", "vm_category_match");
                resultMap.put("matchedCategories", new ArrayList<>(securedVmCategories));
                List<String> matchedIps = filterIpsByProtocol(union(learnedIps, virtualIps), ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal);
                resultMap.put("matchedIps", matchedIps);
                resultMap.put("exception_matching_ips", filterExceptionMatches(union(learnedIps, virtualIps),
                    extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
                if (!ipv6Only && isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_allowed", filterIpv6Addresses(union(learnedIps, virtualIps)));
                }
                if (!ipv6Only && !isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_denied", filterIpv6Addresses(union(learnedIps, virtualIps)));
                }
                if (!ipv4Only) {
                    resultMap.put("ipv4_address_denied", filterIpv4Addresses(union(learnedIps, virtualIps)));
                }
            } else {
                resultMap.put("reason", "VM categories don't match");
            }

            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        } else if (!securedSubnetCategories.isEmpty() && (securedVmCategories.isEmpty() || securedVmCategories.contains("any"))) {
            resultMap.put("ruleType", "subnet_category_only");

            if (isSubsetOf(securedSubnetCategories, subnetCategoriesFromNode)) {
                resultMap.put("matches", true);
                resultMap.put("matchType", "subnet_category_match");
                resultMap.put("matchedCategories", new ArrayList<>(securedSubnetCategories));
                List<String> matchedIps = filterIpsByProtocol(union(learnedIps, virtualIps), ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal);
                resultMap.put("matchedIps", matchedIps);
                resultMap.put("exception_matching_ips", filterExceptionMatches(union(learnedIps, virtualIps),
                    extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
                if (!ipv6Only && isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_allowed", filterIpv6Addresses(union(learnedIps, virtualIps)));
                }
                if (!ipv6Only && !isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_denied", filterIpv6Addresses(union(learnedIps, virtualIps)));
                }
                if (!ipv4Only) {
                    resultMap.put("ipv4_address_denied", filterIpv4Addresses(union(learnedIps, virtualIps)));
                }
            } else {
                resultMap.put("reason", "Subnet categories don't match");
            }

            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        } else if (!securedSubnetCategories.isEmpty() && !securedVmCategories.isEmpty()) {
            resultMap.put("ruleType", "subnet_and_vm_category");

            boolean subnetMatch = isSubsetOf(securedSubnetCategories, subnetCategoriesFromNode);
            boolean vmMatch = isSubsetOf(securedVmCategories, vmCategoriesFromNode);

            if (subnetMatch && vmMatch) {
                resultMap.put("matches", true);
                resultMap.put("matchType", "subnet_and_vm_category_match");
                resultMap.put("matchedSubnetCategories", new ArrayList<>(securedSubnetCategories));
                resultMap.put("matchedVmCategories", new ArrayList<>(securedVmCategories));
                List<String> matchedIps = filterIpsByProtocol(union(learnedIps, virtualIps), ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal);
                resultMap.put("matchedIps", matchedIps);
                resultMap.put("exception_matching_ips", filterExceptionMatches(union(learnedIps, virtualIps),
                    extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
                if (!ipv6Only && isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_allowed", filterIpv6Addresses(union(learnedIps, virtualIps)));
                }
                if (!ipv6Only && !isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_denied", filterIpv6Addresses(union(learnedIps, virtualIps)));
                }
                if (!ipv4Only) {
                    resultMap.put("ipv4_address_denied", filterIpv4Addresses(union(learnedIps, virtualIps)));
                }
            } else {
                resultMap.put("reason", subnetMatch ? "VM categories don't match" : "Subnet categories don't match");
            }

            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        resultMap.put("reason", "No category rules defined");
        resultMap.put("unmatchedIps", computeUnmatchedIps(
            learnedIps,
            virtualIps,
            (List<String>) resultMap.get("matchedIps"),
            (List<String>) resultMap.get("ipv6_address_allowed")
        ));
        return resultMap;
    }

    /**
     * Evaluates if a secured node, VPC, subnet, interface, and VM match based on subnet lists and categories,
     * with an additional check for specific VM names.
     */
    @UserFunction("policy.evaluateSecurityRuleByVmName")
    @Description("Evaluates security policy rules with VM name filtering")
    public Map<String, Object> evaluateSecurityRuleByVmName(
            @Name("securedNode") Node securedNode,
            @Name("vpcNode") Node vpcNode,
            @Name("subnetNode") Node subnetNode,
            @Name("interfaceRel") Relationship interfaceRel,
            @Name("vmNode") Node vmNode,
            @Name("vmNamesToMatch") List<String> vmNamesToMatch) {

        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("matches", false);
        resultMap.put("matchType", "none");
        resultMap.put("matchedVmNames", new ArrayList<String>());
        resultMap.put("unmatchedIps", new ArrayList<String>());
        resultMap.put("exception_matching_ips", new ArrayList<String>());
        resultMap.put("subnetandexceptionNotMatchingIps", new ArrayList<String>());
        resultMap.put("ipv4_address_denied", new ArrayList<String>());
        resultMap.put("ipv6_address_allowed", new ArrayList<String>());
        resultMap.put("ipv6_address_denied", new ArrayList<String>());

        if (securedNode == null || vpcNode == null || subnetNode == null || interfaceRel == null || vmNode == null) {
            return Collections.emptyMap();
        }

        String vpcName = extractPropertyAsString(vpcNode, "name");
        String vpcUuid = extractPropertyAsString(vpcNode, "uuid");
        List<String> externalRouterPrefix = extractPropertyAsList(vpcNode, "external_router_prefix");
        String vmName = extractPropertyAsString(vmNode, "name");
        String vmUuid = extractPropertyAsString(vmNode, "uuid");
        List<String> vmCategories = extractPropertyAsList(vmNode, "vm_category_names");
        String subnetName = extractPropertyAsString(subnetNode, "name");
        String subnetUuid = extractPropertyAsString(subnetNode, "uuid");
        String subnetAdvanceNetworking = extractPropertyAsString(subnetNode, "advance_networking");
        List<String> subnetCategories = extractPropertyAsList(subnetNode, "categories");

        resultMap.put("vpc_name", vpcName);
        resultMap.put("vpc_uuid", vpcUuid);
        resultMap.put("external_router_prefix", new ArrayList<>(externalRouterPrefix));
        resultMap.put("vm_name", vmName);
        resultMap.put("vm_uuid", vmUuid);
        resultMap.put("vmCategories", new ArrayList<>(vmCategories));
        resultMap.put("subnet_name", subnetName);
        resultMap.put("subnet_uuid", subnetUuid);
        resultMap.put("subnet_advance_networking", subnetAdvanceNetworking);
        resultMap.put("subnetCategories", new ArrayList<>(subnetCategories));

        List<String> learnedIps = extractPropertyAsList(interfaceRel, "learned_ips");
        List<String> virtualIps = extractPropertyAsList(interfaceRel, "VIRTUAL_IPS");
        resultMap.put("learnedIps", new ArrayList<>(learnedIps));
        resultMap.put("virtualIps", new ArrayList<>(virtualIps));

        if (vmNamesToMatch == null || vmNamesToMatch.isEmpty()) {
            resultMap.put("reason", "vmNamesToMatch is null or empty");
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        if (vmName == null || !vmNamesToMatch.contains(vmName)) {
            resultMap.put("reason", "VM name doesn't match");
            resultMap.put("requiredNames", new ArrayList<>(vmNamesToMatch));
            resultMap.put("actualName", vmName);
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        // Check for hostnames
        List<String> allIps = union(learnedIps, virtualIps);
        boolean hasHostname = false;
        for (String ip : allIps) {
            if (isHostname(ip)) {
                hasHostname = true;
                break;
            }
        }

        List<String> securedVmCategories = extractPropertyAsList(securedNode, "vm_category_names");
        boolean linkLocal = securedNode.hasProperty("link_local") ? (Boolean) securedNode.getProperty("link_local") : true;

        if (hasHostname) {
            resultMap.put("ruleType", "hostname_vm_category");
            resultMap.put("vmNameMatched", true);
            resultMap.put("matchedVmNames", Collections.singletonList(vmName));
            resultMap.put("vmNamesFilter", new ArrayList<>(vmNamesToMatch));
            if (isSubsetOf(securedVmCategories, vmCategories)) {
                resultMap.put("matches", true);
                resultMap.put("matchType", "vm_category_match");
                List<String> matchedHostnames = new ArrayList<>();
                for (String ip : allIps) {
                    if (isHostname(ip)) {
                        matchedHostnames.add(ip);
                    }
                }
                resultMap.put("matchedIps", matchedHostnames);
                resultMap.put("unmatchedIps", Collections.emptyList());
            } else {
                resultMap.put("reason", "VM categories don't match");
                List<String> unmatchedHostnames = new ArrayList<>();
                for (String ip : allIps) {
                    if (isHostname(ip)) {
                        unmatchedHostnames.add(ip);
                    }
                }
                resultMap.put("unmatchedIps", unmatchedHostnames);
                resultMap.put("matchedIps", Collections.emptyList());
            }
            return resultMap;
        }

        resultMap.put("vmNameMatched", true);
        resultMap.put("matchedVmNames", Collections.singletonList(vmName));
        resultMap.put("vmNamesFilter", new ArrayList<>(vmNamesToMatch));

        Map<String, Object> baseResult = evaluateSecurityRule(securedNode, vpcNode, subnetNode, interfaceRel, vmNode, null, null);
        resultMap.putAll(baseResult);

        resultMap.put("unmatchedIps", computeUnmatchedIps(
            learnedIps,
            virtualIps,
            (List<String>) resultMap.get("matchedIps"),
            (List<String>) resultMap.get("ipv6_address_allowed")
        ));

        return resultMap;
    }

    /**
     * Evaluates if a secured node, VPC, subnet, interface, and VM match based on subnet lists and categories,
     * with an additional check for specific IP addresses.
     */
    @UserFunction("policy.evaluateSecurityRuleByIp")
    @Description("Evaluates security policy rules with IP address filtering")
    public Map<String, Object> evaluateSecurityRuleByIp(
            @Name("securedNode") Node securedNode,
            @Name("vpcNode") Node vpcNode,
            @Name("subnetNode") Node subnetNode,
            @Name("interfaceRel") Relationship interfaceRel,
            @Name("vmNode") Node vmNode,
            @Name("ipsToMatch") List<String> ipsToMatch) {

        Map<String, Object> resultMap = initializeResultMap();

        if (securedNode == null || vpcNode == null || subnetNode == null || interfaceRel == null || vmNode == null) {
            return Collections.emptyMap();
        }

        String vpcName = extractPropertyAsString(vpcNode, "name");
        String vpcUuid = extractPropertyAsString(vpcNode, "uuid");
        List<String> externalRouterPrefix = extractPropertyAsList(vpcNode, "external_router_prefix");
        String vmName = extractPropertyAsString(vmNode, "name");
        String vmUuid = extractPropertyAsString(vmNode, "uuid");
        List<String> vmCategories = extractPropertyAsList(vmNode, "vm_category_names");
        String subnetName = extractPropertyAsString(subnetNode, "name");
        String subnetUuid = extractPropertyAsString(subnetNode, "uuid");
        String subnetAdvanceNetworking = extractPropertyAsString(subnetNode, "advance_networking");
        List<String> subnetCategories = extractPropertyAsList(subnetNode, "categories");

        resultMap.put("vpc_name", vpcName);
        resultMap.put("vpc_uuid", vpcUuid);
        resultMap.put("external_router_prefix", new ArrayList<>(externalRouterPrefix));
        resultMap.put("vm_name", vmName);
        resultMap.put("vm_uuid", vmUuid);
        resultMap.put("vmCategories", new ArrayList<>(vmCategories));
        resultMap.put("subnet_name", subnetName);
        resultMap.put("subnet_uuid", subnetUuid);
        resultMap.put("subnet_advance_networking", subnetAdvanceNetworking);
        resultMap.put("subnetCategories", new ArrayList<>(subnetCategories));

        List<String> learnedIps = extractPropertyAsList(interfaceRel, "learned_ips");
        List<String> virtualIps = extractPropertyAsList(interfaceRel, "VIRTUAL_IPS");
        resultMap.put("learnedIps", new ArrayList<>(learnedIps));
        resultMap.put("virtualIps", new ArrayList<>(virtualIps));

        if (ipsToMatch == null || ipsToMatch.isEmpty()) {
            resultMap.put("reason", "ipsToMatch is null or empty");
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        // Check for hostnames in learnedIps or virtualIps
        List<String> allIps = union(learnedIps, virtualIps);
        boolean hasHostname = false;
        for (String ip : allIps) {
            if (isHostname(ip)) {
                hasHostname = true;
                break;
            }
        }

        List<String> matchedIps = new ArrayList<>();
        List<String> unmatchedIps = new ArrayList<>();
        for (String ip : ipsToMatch) {
            if (ip != null && (learnedIps.contains(ip) || virtualIps.contains(ip))) {
                matchedIps.add(ip);
            } else {
                unmatchedIps.add(ip);
            }
        }

        if (matchedIps.isEmpty()) {
            resultMap.put("reason", "Specified IPs not found in interface's learned IPs or virtual IPs");
            resultMap.put("requiredIps", new ArrayList<>(ipsToMatch));
            resultMap.put("actualIps", new ArrayList<>(union(learnedIps, virtualIps)));
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        resultMap.put("ipMatched", true);

        boolean ipv4Only = securedNode.hasProperty("ipv4_only") ? (Boolean) securedNode.getProperty("ipv4_only") : false;
        boolean ipv6Only = securedNode.hasProperty("ipv6_only") ? (Boolean) securedNode.getProperty("ipv6_only") : false;
        boolean isIpv6TrafficAllowed = securedNode.hasProperty("is_ipv6_traffic_allowed") ? (Boolean) securedNode.getProperty("is_ipv6_traffic_allowed") : false;
        boolean linkLocal = securedNode.hasProperty("link_local") ? (Boolean) securedNode.getProperty("link_local") : true;

        // Handle hostname case
        if (hasHostname) {
            List<String> securedVmCategories = extractPropertyAsList(securedNode, "vm_category_names");
            resultMap.put("ruleType", "hostname_vm_category");
            if (isSubsetOf(securedVmCategories, vmCategories)) {
                resultMap.put("matches", true);
                resultMap.put("matchType", "vm_category_match");
                List<String> matchedHostnames = new ArrayList<>();
                for (String ip : allIps) {
                    if (isHostname(ip)) {
                        matchedHostnames.add(ip);
                    }
                }
                resultMap.put("matchedIps", matchedHostnames);
                resultMap.put("unmatchedIps", Collections.emptyList());
            } else {
                resultMap.put("reason", "VM categories don't match");
                List<String> unmatchedHostnames = new ArrayList<>();
                for (String ip : allIps) {
                    if (isHostname(ip)) {
                        unmatchedHostnames.add(ip);
                    }
                }
                resultMap.put("unmatchedIps", unmatchedHostnames);
                resultMap.put("matchedIps", Collections.emptyList());
            }
            return resultMap;
        }

        List<String> subnetList = extractPropertyAsList(securedNode, "subnet_list");
        if (!subnetList.isEmpty()) {
            List<String> exceptionList = extractPropertyAsList(securedNode, "exception_list");
            resultMap.put("ruleType", "subnet_list");

            Set<String> subnetSet = new HashSet<>(subnetList);
            Set<String> exceptionSet = new HashSet<>(exceptionList);

            List<String> subnetMatchedIps = new ArrayList<>();
            List<String> exceptionMatchingIps = new ArrayList<>();
            List<String> subnetandexceptionNotMatchingIps = new ArrayList<>();
            List<String> ipv4Denied = new ArrayList<>();
            List<String> ipv6Allowed = new ArrayList<>();
            List<String> ipv6Denied = new ArrayList<>();

            for (String ip : matchedIps) {
                if (ip == null) continue;
                boolean isLinkLocalIp = isLinkLocal(ip);
                if (!linkLocal && isLinkLocalIp) continue;
                boolean inSubnetList = isIpInSubnetList(ip, subnetList);
                boolean inExceptionList = isIpInSubnetList(ip, exceptionList);
                boolean isIPv4 = isIPv4(ip);

                boolean includeIp = false;
                if (ipv4Only && ipv6Only) {
                    includeIp = true;
                } else if (ipv4Only && !ipv6Only && isIPv4) {
                    includeIp = true;
                } else if (!ipv4Only && ipv6Only && !isIPv4) {
                    includeIp = true;
                } else if (!ipv4Only && !ipv6Only) {
                    if (!isIPv4 && isIpv6TrafficAllowed) {
                        ipv6Allowed.add(ip);
                        includeIp = true;
                    } else if (!isIPv4 && !isIpv6TrafficAllowed) {
                        ipv6Denied.add(ip);
                    } else if (isIPv4) {
                        ipv4Denied.add(ip);
                    }
                }

                if (inSubnetList && !inExceptionList && includeIp) {
                    subnetMatchedIps.add(ip);
                }

                if (inSubnetList && inExceptionList && includeIp) {
                    exceptionMatchingIps.add(ip);
                }

                if (!inSubnetList && !inExceptionList) {
                    subnetandexceptionNotMatchingIps.add(ip);
                }
            }

            resultMap.put("matchedIps", subnetMatchedIps);
            resultMap.put("exception_matching_ips", filterExceptionMatches(matchedIps, subnetList, exceptionList, ipv4Only, ipv6Only));
            resultMap.put("subnetandexceptionNotMatchingIps", subnetandexceptionNotMatchingIps);
            resultMap.put("ipv4_address_denied", ipv4Denied);
            resultMap.put("ipv6_address_allowed", ipv6Allowed);
            resultMap.put("ipv6_address_denied", ipv6Denied);

            if (!subnetMatchedIps.isEmpty()) {
                resultMap.put("matches", true);
                resultMap.put("matchType", "ip_subnet_match");
                resultMap.put("matchedWith", "direct_subnet_list");
            } else if (!exceptionMatchingIps.isEmpty()) {
                resultMap.put("matches", true);
                resultMap.put("matchType", "exception_IP_matched");
                resultMap.put("matchedWith", "direct_subnet_list");
            } else {
                resultMap.put("reason", "IPs not found in subnet list");
            }

            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                subnetMatchedIps,
                ipv6Allowed
            ));
            return resultMap;
        } else {
            List<String> securedSubnetCategories = extractPropertyAsList(securedNode, "subnet_category_names");
            List<String> securedVmCategories = extractPropertyAsList(securedNode, "vm_category_names");
            List<String> subnetCategoriesFromNode = extractPropertyAsList(subnetNode, "categories");
            List<String> vmCategoriesFromNode = extractPropertyAsList(vmNode, "vm_category_names");

            resultMap.put("securedSubnetCategories", new ArrayList<>(securedSubnetCategories));
            resultMap.put("securedVmCategories", new ArrayList<>(securedVmCategories));
            resultMap.put("actualSubnetCategories", new ArrayList<>(subnetCategoriesFromNode));
            resultMap.put("actualVmCategories", new ArrayList<>(vmCategoriesFromNode));

            if (securedSubnetCategories.contains("any") && securedVmCategories.contains("any")) {
                resultMap.put("matches", true);
                resultMap.put("matchType", "any_any_match");
                List<String> filteredMatchedIps = filterIpsByProtocol(matchedIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal);
                resultMap.put("matchedIps", filteredMatchedIps);
                resultMap.put("exception_matching_ips", filterExceptionMatches(matchedIps,
                    extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
                if (!ipv6Only && isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_allowed", filterIpv6Addresses(matchedIps));
                }
                if (!ipv6Only && !isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_denied", filterIpv6Addresses(matchedIps));
                }
                if (!ipv4Only) {
                    resultMap.put("ipv4_address_denied", filterIpv4Addresses(matchedIps));
                }
                resultMap.put("unmatchedIps", computeUnmatchedIps(
                    learnedIps,
                    virtualIps,
                    filteredMatchedIps,
                    (List<String>) resultMap.get("ipv6_address_allowed")
                ));
                return resultMap;
            }

            boolean hasSubnetCategories = !securedSubnetCategories.isEmpty();
            boolean hasVmCategories = !securedVmCategories.isEmpty();

            if (!hasSubnetCategories && !hasVmCategories) {
                resultMap.put("reason", "All secured node properties are null or empty; no criteria to evaluate");
                resultMap.put("unmatchedIps", computeUnmatchedIps(
                    learnedIps,
                    virtualIps,
                    (List<String>) resultMap.get("matchedIps"),
                    (List<String>) resultMap.get("ipv6_address_allowed")
                ));
                return resultMap;
            }

            if ((securedSubnetCategories.isEmpty() || securedSubnetCategories.contains("any")) && !securedVmCategories.isEmpty()) {
                resultMap.put("ruleType", "vm_category_only");

                if (isSubsetOf(securedVmCategories, vmCategoriesFromNode)) {
                    resultMap.put("matches", true);
                    resultMap.put("matchType", "vm_category_match");
                    resultMap.put("matchedCategories", new ArrayList<>(securedVmCategories));
                    List<String> filteredMatchedIps = filterIpsByProtocol(matchedIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal);
                    resultMap.put("matchedIps", filteredMatchedIps);
                    resultMap.put("exception_matching_ips", filterExceptionMatches(matchedIps,
                        extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
                    if (!ipv6Only && isIpv6TrafficAllowed) {
                        resultMap.put("ipv6_address_allowed", filterIpv6Addresses(matchedIps));
                    }
                    if (!ipv6Only && !isIpv6TrafficAllowed) {
                        resultMap.put("ipv6_address_denied", filterIpv6Addresses(matchedIps));
                    }
                    if (!ipv4Only) {
                        resultMap.put("ipv4_address_denied", filterIpv4Addresses(matchedIps));
                    }
                } else {
                    resultMap.put("reason", "VM categories don't match");
                }

                resultMap.put("unmatchedIps", computeUnmatchedIps(
                    learnedIps,
                    virtualIps,
                    (List<String>) resultMap.get("matchedIps"),
                    (List<String>) resultMap.get("ipv6_address_allowed")
                ));
                return resultMap;
            } else if (!securedSubnetCategories.isEmpty() && (securedVmCategories.isEmpty() || securedVmCategories.contains("any"))) {
                resultMap.put("ruleType", "subnet_category_only");

                if (isSubsetOf(securedSubnetCategories, subnetCategoriesFromNode)) {
                    resultMap.put("matches", true);
                    resultMap.put("matchType", "subnet_category_match");
                    resultMap.put("matchedCategories", new ArrayList<>(securedSubnetCategories));
                    List<String> filteredMatchedIps = filterIpsByProtocol(matchedIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal);
                    resultMap.put("matchedIps", filteredMatchedIps);
                    resultMap.put("exception_matching_ips", filterExceptionMatches(matchedIps,
                        extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
                    if (!ipv6Only && isIpv6TrafficAllowed) {
                        resultMap.put("ipv6_address_allowed", filterIpv6Addresses(matchedIps));
                    }
                    if (!ipv6Only && !isIpv6TrafficAllowed) {
                        resultMap.put("ipv6_address_denied", filterIpv6Addresses(matchedIps));
                    }
                    if (!ipv4Only) {
                        resultMap.put("ipv4_address_denied", filterIpv4Addresses(matchedIps));
                    }
                } else {
                    resultMap.put("reason", "Subnet categories don't match");
                }

                resultMap.put("unmatchedIps", computeUnmatchedIps(
                    learnedIps,
                    virtualIps,
                    (List<String>) resultMap.get("matchedIps"),
                    (List<String>) resultMap.get("ipv6_address_allowed")
                ));
                return resultMap;
            } else if (!securedSubnetCategories.isEmpty() && !securedVmCategories.isEmpty()) {
                resultMap.put("ruleType", "subnet_and_vm_category");

                if (isSubsetOf(securedSubnetCategories, subnetCategoriesFromNode) &&
                    isSubsetOf(securedVmCategories, vmCategoriesFromNode)) {
                    resultMap.put("matches", true);
                    resultMap.put("matchType", "subnet_and_vm_category_match");
                    resultMap.put("matchedSubnetCategories", new ArrayList<>(securedSubnetCategories));
                    resultMap.put("matchedVmCategories", new ArrayList<>(securedVmCategories));
                    List<String> filteredMatchedIps = filterIpsByProtocol(matchedIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal);
                    resultMap.put("matchedIps", filteredMatchedIps);
                    resultMap.put("exception_matching_ips", filterExceptionMatches(matchedIps,
                        extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
                    if (!ipv6Only && isIpv6TrafficAllowed) {
                        resultMap.put("ipv6_address_allowed", filterIpv6Addresses(matchedIps));
                    }
                    if (!ipv6Only && !isIpv6TrafficAllowed) {
                        resultMap.put("ipv6_address_denied", filterIpv6Addresses(matchedIps));
                    }
                    if (!ipv4Only) {
                        resultMap.put("ipv4_address_denied", filterIpv4Addresses(matchedIps));
                    }
                } else {
                    resultMap.put("reason", "Categories don't match");
                }

                resultMap.put("unmatchedIps", computeUnmatchedIps(
                    learnedIps,
                    virtualIps,
                    (List<String>) resultMap.get("matchedIps"),
                    (List<String>) resultMap.get("ipv6_address_allowed")
                ));
                return resultMap;
            }

            resultMap.put("reason", "No category rules defined");
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }
    }

    /**
     * Helper function to check if an IP is present in a list of subnets or IP addresses.
     */
    @UserFunction("policy.isIpInSubnetList")
    @Description("Checks if an IP is present in a list of subnets or IPs")
    public boolean isIpInSubnetList(
            @Name("ip") String ip,
            @Name("subnetList") List<String> subnetList) {

        if (ip == null || subnetList == null || subnetList.isEmpty() || isHostname(ip)) {
            return false;
        }

        try {
            InetAddress ipAddress = InetAddress.getByName(ip);
            boolean isIPv4 = ipAddress.getAddress().length == 4;

            for (String subnet : subnetList) {
                if (subnet == null) continue;
                if (!subnet.contains("/")) {
                    try {
                        InetAddress subnetAddress = InetAddress.getByName(subnet);
                        if (Arrays.equals(ipAddress.getAddress(), subnetAddress.getAddress())) {
                            return true;
                        }
                    } catch (UnknownHostException e) {
                        continue;
                    }
                } else {
                    if (isIPv4 && subnet.contains(".")) {
                        try {
                            SubnetUtils utils = new SubnetUtils(subnet);
                            utils.setInclusiveHostCount(true);
                            if (utils.getInfo().isInRange(ip)) {
                                return true;
                            }
                        } catch (IllegalArgumentException e) {
                            continue;
                        }
                    } else if (!isIPv4 && subnet.contains(":")) {
                        try {
                            String[] parts = subnet.split("/");
                            if (parts.length != 2) {
                                continue;
                            }
                            String subnetAddr = parts[0];
                            int prefixLength = Integer.parseInt(parts[1]);

                            byte[] ipBytes = ipAddress.getAddress();
                            byte[] subnetBytes = InetAddress.getByName(subnetAddr).getAddress();

                            int fullBytes = prefixLength / 8;
                            int remainingBits = prefixLength % 8;

                            boolean fullByteMatch = true;
                            for (int i = 0; i < fullBytes && i < ipBytes.length; i++) {
                                if (ipBytes[i] != subnetBytes[i]) {
                                    fullByteMatch = false;
                                    break;
                                }
                            }

                            if (!fullByteMatch) {
                                continue; // Try next subnet
                            }

                            if (remainingBits > 0 && fullBytes < ipBytes.length) {
                                int mask = 0xFF << (8 - remainingBits);
                                if ((ipBytes[fullBytes] & mask) != (subnetBytes[fullBytes] & mask)) {
                                    continue; // Try next subnet
                                }
                            }

                            return true;
                        } catch (Exception e) {
                            continue;
                        }
                    }
                }
            }

            return false;
        } catch (UnknownHostException e) {
            return false;
        }
    }
/**
     * Evaluates if a secured node, VPC, subnet, interface, VM, and service group match based on IP and ports.
     */
    @UserFunction("policy.evaluateSecurityRuleByIpSG")
    @Description("Evaluates security policy rules with IP and service group filtering")
    public Map<String, Object> evaluateSecurityRuleByIpSG(
            @Name("securedNode") Node securedNode,
            @Name("vpcNode") Node vpcNode,
            @Name("subnetNode") Node subnetNode,
            @Name("interfaceRel") Relationship interfaceRel,
            @Name("vmNode") Node vmNode,
            @Name("serviceGroupNode") Node serviceGroupNode,
            @Name("ipsToMatch") List<String> ipsToMatch,
            @Name("tcpPorts") List<String> tcpPorts,
            @Name("udpPorts") List<String> udpPorts,
            @Name("icmpTypes") List<String> icmpTypes) {

        Map<String, Object> resultMap = initializeResultMap();

        if (securedNode == null || vpcNode == null || subnetNode == null || interfaceRel == null ||
            vmNode == null || serviceGroupNode == null) {
            return Collections.emptyMap();
        }

        String vpcName = extractPropertyAsString(vpcNode, "name");
        String vpcUuid = extractPropertyAsString(vpcNode, "uuid");
        List<String> externalRouterPrefix = extractPropertyAsList(vpcNode, "external_router_prefix");
        String vmName = extractPropertyAsString(vmNode, "name");
        String vmUuid = extractPropertyAsString(vmNode, "uuid");
        List<String> vmCategories = extractPropertyAsList(vmNode, "vm_category_names");
        String subnetName = extractPropertyAsString(subnetNode, "name");
        String subnetUuid = extractPropertyAsString(subnetNode, "uuid");
        String subnetAdvanceNetworking = extractPropertyAsString(subnetNode, "advance_networking");
        List<String> subnetCategories = extractPropertyAsList(subnetNode, "categories");

        resultMap.put("vpc_name", vpcName);
        resultMap.put("vpc_uuid", vpcUuid);
        resultMap.put("external_router_prefix", new ArrayList<>(externalRouterPrefix));
        resultMap.put("vm_name", vmName);
        resultMap.put("vm_uuid", vmUuid);
        resultMap.put("vmCategories", new ArrayList<>(vmCategories));
        resultMap.put("subnet_name", subnetName);
        resultMap.put("subnet_uuid", subnetUuid);
        resultMap.put("subnet_advance_networking", subnetAdvanceNetworking);
        resultMap.put("subnetCategories", new ArrayList<>(subnetCategories));

        List<String> learnedIps = extractPropertyAsList(interfaceRel, "learned_ips");
        List<String> virtualIps = extractPropertyAsList(interfaceRel, "VIRTUAL_IPS");
        resultMap.put("learnedIps", new ArrayList<>(learnedIps));
        resultMap.put("virtualIps", new ArrayList<>(virtualIps));

        // Check for hostnames
        List<String> allIps = union(learnedIps, virtualIps);
        boolean hasHostname = false;
        for (String ip : allIps) {
            if (isHostname(ip)) {
                hasHostname = true;
                break;
            }
        }

        Map<String, Object> serviceGroupResult = isServiceGroupMatchWithDetails(
                serviceGroupNode, tcpPorts, udpPorts, icmpTypes);

        if (!(Boolean)serviceGroupResult.get("matches")) {
            resultMap.put("reason", "Service group mismatch");
            resultMap.put("matchType", "none");
            resultMap.put("serviceGroupDetails", serviceGroupResult);
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        // Handle hostname case
        if (hasHostname) {
            List<String> securedVmCategories = extractPropertyAsList(securedNode, "vm_category_names");
            resultMap.put("ruleType", "hostname_vm_category");
            resultMap.put("serviceGroupMatched", true);
            resultMap.put("serviceGroupDetails", serviceGroupResult);
            if (isSubsetOf(securedVmCategories, vmCategories)) {
                resultMap.put("matches", true);
                resultMap.put("matchType", "vm_category_match");
                List<String> matchedHostnames = new ArrayList<>();
                for (String ip : allIps) {
                    if (isHostname(ip)) {
                        matchedHostnames.add(ip);
                    }
                }
                resultMap.put("matchedIps", matchedHostnames);
                resultMap.put("unmatchedIps", Collections.emptyList());
            } else {
                resultMap.put("reason", "VM categories don't match");
                List<String> unmatchedHostnames = new ArrayList<>();
                for (String ip : allIps) {
                    if (isHostname(ip)) {
                        unmatchedHostnames.add(ip);
                    }
                }
                resultMap.put("unmatchedIps", unmatchedHostnames);
                resultMap.put("matchedIps", Collections.emptyList());
            }
            return resultMap;
        }

        Map<String, Object> ipRuleResult = evaluateSecurityRuleByIp(
                securedNode, vpcNode, subnetNode, interfaceRel, vmNode, ipsToMatch);

        resultMap.putAll(ipRuleResult);

        resultMap.put("serviceGroupMatched", true);
        resultMap.put("serviceGroupDetails", serviceGroupResult);

        resultMap.put("unmatchedIps", computeUnmatchedIps(
            learnedIps,
            virtualIps,
            (List<String>) resultMap.get("matchedIps"),
            (List<String>) resultMap.get("ipv6_address_allowed")
        ));

        return resultMap;
    }

    /**
     * Evaluates if a secured node, VPC, subnet, interface, VM, and service group match based on VM name and ports.
     */
    @UserFunction("policy.evaluateSecurityRuleByVmNameSG")
    @Description("Evaluates security policy rules with VM name and service group filtering")
    public Map<String, Object> evaluateSecurityRuleByVmNameSG(
            @Name("securedNode") Node securedNode,
            @Name("vpcNode") Node vpcNode,
            @Name("subnetNode") Node subnetNode,
            @Name("interfaceRel") Relationship interfaceRel,
            @Name("vmNode") Node vmNode,
            @Name("serviceGroupNode") Node serviceGroupNode,
            @Name("vmNamesToMatch") List<String> vmNamesToMatch,
            @Name("tcpPorts") List<String> tcpPorts,
            @Name("udpPorts") List<String> udpPorts,
            @Name("icmpTypes") List<String> icmpTypes) {

        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("matches", false);
        resultMap.put("matchType", "none");
        resultMap.put("matchedVmNames", new ArrayList<String>());
        resultMap.put("unmatchedIps", new ArrayList<String>());
        resultMap.put("exception_matching_ips", new ArrayList<String>());
        resultMap.put("subnetandexceptionNotMatchingIps", new ArrayList<String>());
        resultMap.put("ipv4_address_denied", new ArrayList<String>());
        resultMap.put("ipv6_address_allowed", new ArrayList<String>());
        resultMap.put("ipv6_address_denied", new ArrayList<String>());

        if (securedNode == null || vpcNode == null || subnetNode == null || interfaceRel == null ||
            vmNode == null || serviceGroupNode == null) {
            return Collections.emptyMap();
        }

        String vpcName = extractPropertyAsString(vpcNode, "name");
        String vpcUuid = extractPropertyAsString(vpcNode, "uuid");
        List<String> externalRouterPrefix = extractPropertyAsList(vpcNode, "external_router_prefix");
        String vmName = extractPropertyAsString(vmNode, "name");
        String vmUuid = extractPropertyAsString(vmNode, "uuid");
        List<String> vmCategories = extractPropertyAsList(vmNode, "vm_category_names");
        String subnetName = extractPropertyAsString(subnetNode, "name");
        String subnetUuid = extractPropertyAsString(subnetNode, "uuid");
        String subnetAdvanceNetworking = extractPropertyAsString(subnetNode, "advance_networking");
        List<String> subnetCategories = extractPropertyAsList(subnetNode, "categories");

        resultMap.put("vpc_name", vpcName);
        resultMap.put("vpc_uuid", vpcUuid);
        resultMap.put("external_router_prefix", new ArrayList<>(externalRouterPrefix));
        resultMap.put("vm_name", vmName);
        resultMap.put("vm_uuid", vmUuid);
        resultMap.put("vmCategories", new ArrayList<>(vmCategories));
        resultMap.put("subnet_name", subnetName);
        resultMap.put("subnet_uuid", subnetUuid);
        resultMap.put("subnet_advance_networking", subnetAdvanceNetworking);
        resultMap.put("subnetCategories", new ArrayList<>(subnetCategories));

        List<String> learnedIps = extractPropertyAsList(interfaceRel, "learned_ips");
        List<String> virtualIps = extractPropertyAsList(interfaceRel, "VIRTUAL_IPS");
        resultMap.put("learnedIps", new ArrayList<>(learnedIps));
        resultMap.put("virtualIps", new ArrayList<>(virtualIps));

        // Check for hostnames
        List<String> allIps = union(learnedIps, virtualIps);
        boolean hasHostname = false;
        for (String ip : allIps) {
            if (isHostname(ip)) {
                hasHostname = true;
                break;
            }
        }

        List<String> sgTcpPorts = extractPropertyAsList(serviceGroupNode, "tcp");
        List<String> sgUdpPorts = extractPropertyAsList(serviceGroupNode, "udp");

        if (sgTcpPorts.contains("all") || sgUdpPorts.contains("all")) {
            if (hasHostname) {
                resultMap.put("ruleType", "hostname_vm_category");
                resultMap.put("serviceGroupMatched", true);
                resultMap.put("serviceGroupDetails", Map.of(
                    "matches", true,
                    "reason", "all_ports_allowed",
                    "sgTcpPorts", new ArrayList<>(sgTcpPorts),
                    "sgUdpPorts", new ArrayList<>(sgUdpPorts)
                ));
                if (vmNamesToMatch != null && vmName != null && vmNamesToMatch.contains(vmName)) {
                    List<String> securedVmCategories = extractPropertyAsList(securedNode, "vm_category_names");
                    resultMap.put("vmNameMatched", true);
                    resultMap.put("matchedVmNames", Collections.singletonList(vmName));
                    resultMap.put("vmNamesFilter", new ArrayList<>(vmNamesToMatch));
                    if (isSubsetOf(securedVmCategories, vmCategories)) {
                        resultMap.put("matches", true);
                        resultMap.put("matchType", "vm_category_match");
                        List<String> matchedHostnames = new ArrayList<>();
                        for (String ip : allIps) {
                            if (isHostname(ip)) {
                                matchedHostnames.add(ip);
                            }
                        }
                        resultMap.put("matchedIps", matchedHostnames);
                        resultMap.put("unmatchedIps", Collections.emptyList());
                    } else {
                        resultMap.put("reason", "VM categories don't match");
                        List<String> unmatchedHostnames = new ArrayList<>();
                        for (String ip : allIps) {
                            if (isHostname(ip)) {
                                unmatchedHostnames.add(ip);
                            }
                        }
                        resultMap.put("unmatchedIps", unmatchedHostnames);
                        resultMap.put("matchedIps", Collections.emptyList());
                    }
                } else {
                    resultMap.put("reason", "VM name doesn't match");
                    resultMap.put("requiredNames", new ArrayList<>(vmNamesToMatch));
                    resultMap.put("actualName", vmName);
                    List<String> unmatchedHostnames = new ArrayList<>();
                    for (String ip : allIps) {
                        if (isHostname(ip)) {
                            unmatchedHostnames.add(ip);
                        }
                    }
                    resultMap.put("unmatchedIps", unmatchedHostnames);
                    resultMap.put("matchedIps", Collections.emptyList());
                }
                return resultMap;
            }

            Map<String, Object> vmNameRuleResult = evaluateSecurityRuleByVmName(
                    securedNode, vpcNode, subnetNode, interfaceRel, vmNode, vmNamesToMatch);

            resultMap.putAll(vmNameRuleResult);

            resultMap.put("serviceGroupMatched", true);
            resultMap.put("serviceGroupDetails", Map.of(
                "matches", true,
                "reason", "all_ports_allowed",
                "sgTcpPorts", new ArrayList<>(sgTcpPorts),
                "sgUdpPorts", new ArrayList<>(sgUdpPorts)
            ));

            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));

            return resultMap;
        }

        Map<String, Object> serviceGroupResult = isServiceGroupMatchWithDetails(
                serviceGroupNode, tcpPorts, udpPorts, icmpTypes);

        if (!(Boolean)serviceGroupResult.get("matches")) {
            resultMap.put("reason", "Service group mismatch");
            resultMap.put("matchType", "none");
            resultMap.put("serviceGroupDetails", serviceGroupResult);
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        if (hasHostname) {
            resultMap.put("ruleType", "hostname_vm_category");
            resultMap.put("serviceGroupMatched", true);
            resultMap.put("serviceGroupDetails", serviceGroupResult);
            if (vmNamesToMatch != null && vmName != null && vmNamesToMatch.contains(vmName)) {
                List<String> securedVmCategories = extractPropertyAsList(securedNode, "vm_category_names");
                resultMap.put("vmNameMatched", true);
                resultMap.put("matchedVmNames", Collections.singletonList(vmName));
                resultMap.put("vmNamesFilter", new ArrayList<>(vmNamesToMatch));
                if (isSubsetOf(securedVmCategories, vmCategories)) {
                    resultMap.put("matches", true);
                    resultMap.put("matchType", "vm_category_match");
                    List<String> matchedHostnames = new ArrayList<>();
                    for (String ip : allIps) {
                        if (isHostname(ip)) {
                            matchedHostnames.add(ip);
                        }
                    }
                    resultMap.put("matchedIps", matchedHostnames);
                    resultMap.put("unmatchedIps", Collections.emptyList());
                } else {
                    resultMap.put("reason", "VM categories don't match");
                    List<String> unmatchedHostnames = new ArrayList<>();
                    for (String ip : allIps) {
                        if (isHostname(ip)) {
                            unmatchedHostnames.add(ip);
                        }
                    }
                    resultMap.put("unmatchedIps", unmatchedHostnames);
                    resultMap.put("matchedIps", Collections.emptyList());
                }
            } else {
                resultMap.put("reason", "VM name doesn't match");
                resultMap.put("requiredNames", new ArrayList<>(vmNamesToMatch));
                resultMap.put("actualName", vmName);
                List<String> unmatchedHostnames = new ArrayList<>();
                for (String ip : allIps) {
                    if (isHostname(ip)) {
                        unmatchedHostnames.add(ip);
                    }
                }
                resultMap.put("unmatchedIps", unmatchedHostnames);
                resultMap.put("matchedIps", Collections.emptyList());
            }
            return resultMap;
        }

        Map<String, Object> vmNameRuleResult = evaluateSecurityRuleByVmName(
                securedNode, vpcNode, subnetNode, interfaceRel, vmNode, vmNamesToMatch);

        resultMap.putAll(vmNameRuleResult);

        resultMap.put("serviceGroupMatched", true);
        resultMap.put("serviceGroupDetails", serviceGroupResult);

        resultMap.put("unmatchedIps", computeUnmatchedIps(
            learnedIps,
            virtualIps,
            (List<String>) resultMap.get("matchedIps"),
            (List<String>) resultMap.get("ipv6_address_allowed")
        ));

        return resultMap;
    }

    /**
     * Evaluates if a VM is unresolved based on partial or no category matches with the secured node's requirements.
     */
    @UserFunction("policy.evaluateUnresolvedVms")
    @Description("Identifies unresolved VMs based on partial or no category matches with secured node requirements, including host and cluster information")
    public Map<String, Object> evaluateUnresolvedVms(
            @Name("securedNode") Node securedNode,
            @Name("vpcNode") Node vpcNode,
            @Name("subnetNode") Node subnetNode,
            @Name("interfaceRel") Relationship interfaceRel,
            @Name("vmNode") Node vmNode,
            @Name(value = "hostNode", defaultValue = "null") Node hostNode,
            @Name(value = "clusterNode", defaultValue = "null") Node clusterNode) {

        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("isUnresolved", false);
        resultMap.put("scenario", "none");
        resultMap.put("priority", 0);
        resultMap.put("matchedIps", new ArrayList<String>());
        resultMap.put("unmatchedIps", new ArrayList<String>());
        resultMap.put("exception_matching_ips", new ArrayList<String>());
        resultMap.put("subnetandexceptionNotMatchingIps", new ArrayList<String>());
        resultMap.put("ipv4_address_denied", new ArrayList<String>());
        resultMap.put("ipv6_address_allowed", new ArrayList<String>());
        resultMap.put("ipv6_address_denied", new ArrayList<String>());

        if (securedNode == null || vpcNode == null || subnetNode == null || interfaceRel == null || vmNode == null) {
            return Collections.emptyMap();
        }

        String vpcName = extractPropertyAsString(vpcNode, "name");
        String vpcUuid = extractPropertyAsString(vpcNode, "uuid");
        List<String> externalRouterPrefix = extractPropertyAsList(vpcNode, "external_router_prefix");
        String vmName = extractPropertyAsString(vmNode, "name");
        String vmUuid = extractPropertyAsString(vmNode, "uuid");
        List<String> vmCategories = extractPropertyAsList(vmNode, "vm_category_names");
        String subnetName = extractPropertyAsString(subnetNode, "name");
        String subnetUuid = extractPropertyAsString(subnetNode, "uuid");
        String subnetAdvanceNetworking = extractPropertyAsString(subnetNode, "advance_networking");
        List<String> subnetCategories = extractPropertyAsList(subnetNode, "categories");

        resultMap.put("vpc_name", vpcName);
        resultMap.put("vpc_uuid", vpcUuid);
        resultMap.put("external_router_prefix", new ArrayList<>(externalRouterPrefix));
        resultMap.put("vm_name", vmName);
        resultMap.put("vm_uuid", vmUuid);
        resultMap.put("vmCategories", new ArrayList<>(vmCategories));
        resultMap.put("subnet_name", subnetName);
        resultMap.put("subnet_uuid", subnetUuid);
        resultMap.put("subnet_advance_networking", subnetAdvanceNetworking);
        resultMap.put("subnetCategories", new ArrayList<>(subnetCategories));

        // Add host node information if present
        if (hostNode != null) {
            String hostName = extractPropertyAsString(hostNode, "name");
            String hostUuid = extractPropertyAsString(hostNode, "uuid");
            String hostIp = extractPropertyAsString(hostNode, "ip_address");
            resultMap.put("host_name", hostName);
            resultMap.put("host_uuid", hostUuid);
            resultMap.put("host_ip", hostIp);
        }

        // Add cluster node information if present
        if (clusterNode != null) {
            String clusterName = extractPropertyAsString(clusterNode, "name");
            String clusterUuid = extractPropertyAsString(clusterNode, "uuid");
            String clusterIp = extractPropertyAsString(clusterNode, "ip_address");
            resultMap.put("cluster_name", clusterName);
            resultMap.put("cluster_uuid", clusterUuid);
            resultMap.put("cluster_ip", clusterIp);
        }

        // Add mac address if present in vmNode

        String macAddress = extractPropertyAsString(interfaceRel, "mac");
        resultMap.put("mac", macAddress);

        String vmPower = extractPropertyAsString(vmNode, "power_state");
        resultMap.put("vmPower", vmPower);

        // Add hash if present in securedNode
        if (securedNode.hasProperty("hash")) {
            String hash = extractPropertyAsString(securedNode, "hash");
            resultMap.put("hash", hash);
        }

        List<String> learnedIps = extractPropertyAsList(interfaceRel, "learned_ips");
        List<String> virtualIps = extractPropertyAsList(interfaceRel, "VIRTUAL_IPS");
        if (learnedIps == null) learnedIps = Collections.emptyList();
        if (virtualIps == null) virtualIps = Collections.emptyList();
        resultMap.put("learnedIps", new ArrayList<>(learnedIps));
        resultMap.put("virtualIps", new ArrayList<>(virtualIps));

        List<String> filteredIps = union(learnedIps, virtualIps);

        // Check for hostnames
        boolean hasHostname = false;
        for (String ip : filteredIps) {
            if (isHostname(ip)) {
                hasHostname = true;
                break;
            }
        }

        List<String> securedSubnetCategories = extractPropertyAsList(securedNode, "subnet_category_names");
        List<String> securedVmCategories = extractPropertyAsList(securedNode, "vm_category_names");
        boolean ipv4Only = securedNode.hasProperty("ipv4_only") ? (Boolean) securedNode.getProperty("ipv4_only") : false;
        boolean ipv6Only = securedNode.hasProperty("ipv6_only") ? (Boolean) securedNode.getProperty("ipv6_only") : false;
        boolean isIpv6TrafficAllowed = securedNode.hasProperty("is_ipv6_traffic_allowed") ? (Boolean) securedNode.getProperty("is_ipv6_traffic_allowed") : false;
        boolean linkLocal = securedNode.hasProperty("link_local") ? (Boolean) securedNode.getProperty("link_local") : true;

        resultMap.put("securedSubnetCategories", new ArrayList<>(securedSubnetCategories));
        resultMap.put("securedVmCategories", new ArrayList<>(securedVmCategories));

        // Handle hostname case
        if (hasHostname) {
            resultMap.put("ruleType", "hostname_vm_category");
            List<String> matchedHostnames = new ArrayList<>();
            for (String ip : filteredIps) {
                if (isHostname(ip)) {
                    matchedHostnames.add(ip);
                }
            }

            // Check for full VM category match
            if (isSubsetOf(securedVmCategories, vmCategories)) {
                resultMap.put("reason", "VM is resolved: VM categories match with hostname");
                resultMap.put("matchedIps", matchedHostnames);
                resultMap.put("unmatchedIps", Collections.emptyList());
                return resultMap;
            }

            // VM is unresolved
            resultMap.put("isUnresolved", true);
            resultMap.put("matchedIps", matchedHostnames);
            resultMap.put("unmatchedIps", Collections.emptyList());

            // Check for partial VM category match
            Set<String> securedVmCategorySet = new HashSet<>(securedVmCategories);
            Set<String> vmCategorySet = new HashSet<>(vmCategories);
            boolean hasVmCategories = !securedVmCategories.isEmpty();
            boolean partialVmMatch = hasVmCategories && !Collections.disjoint(securedVmCategorySet, vmCategorySet);

            if (partialVmMatch) {
                resultMap.put("scenario", "partial_category_match");
                resultMap.put("priority", 2);
                resultMap.put("reason", "Partial VM category match: some VM categories match with hostname");
                resultMap.put("partialVmMatch", true);
                resultMap.put("partialSubnetMatch", false);
            } else {
                resultMap.put("scenario", "no_category_match");
                resultMap.put("priority", 1);
                resultMap.put("reason", "No VM categories match with hostname");
                resultMap.put("partialVmMatch", false);
                resultMap.put("partialSubnetMatch", false);
            }

            return resultMap;
        }

        // Normal IP case
        List<String> subnetList = extractPropertyAsList(securedNode, "subnet_list");
        if (!subnetList.isEmpty()) {
            List<String> exceptionList = extractPropertyAsList(securedNode, "exception_list");

            Set<String> subnetSet = new HashSet<>(subnetList);
            Set<String> exceptionSet = new HashSet<>(exceptionList);

            List<String> matchedIps = new ArrayList<>();
            List<String> exceptionMatchingIps = new ArrayList<>();
            List<String> subnetandexceptionNotMatchingIps = new ArrayList<>();
            List<String> ipv4Denied = new ArrayList<>();
            List<String> ipv6Allowed = new ArrayList<>();
            List<String> ipv6Denied = new ArrayList<>();

            for (String ip : filteredIps) {
                if (ip == null) continue;
                boolean isLinkLocalIp = isLinkLocal(ip);
                if (!linkLocal && isLinkLocalIp) continue;
                boolean inSubnetList = isIpInSubnetList(ip, subnetList);
                boolean inExceptionList = isIpInSubnetList(ip, exceptionList);
                boolean isIPv4 = isIPv4(ip);

                boolean includeIp = false;
                if (ipv4Only && ipv6Only) {
                    includeIp = true;
                } else if (ipv4Only && !ipv6Only && isIPv4) {
                    includeIp = true;
                } else if (!ipv4Only && ipv6Only && !isIPv4) {
                    includeIp = true;
                } else if (!ipv4Only && !ipv6Only) {
                    if (!isIPv4 && isIpv6TrafficAllowed) {
                        ipv6Allowed.add(ip);
                        includeIp = true;
                    } else if (!isIPv4 && !isIpv6TrafficAllowed) {
                        ipv6Denied.add(ip);
                    } else if (isIPv4) {
                        ipv4Denied.add(ip);
                    }
                }

                if (inSubnetList && !inExceptionList && includeIp) {
                    matchedIps.add(ip);
                }

                if (inSubnetList && inExceptionList && includeIp) {
                    exceptionMatchingIps.add(ip);
                }

                if (!inSubnetList && !inExceptionList) {
                    subnetandexceptionNotMatchingIps.add(ip);
                }
            }

            resultMap.put("matchedIps", matchedIps);
            resultMap.put("exception_matching_ips", filterExceptionMatches(filteredIps, subnetList, exceptionList, ipv4Only, ipv6Only));
            resultMap.put("subnetandexceptionNotMatchingIps", subnetandexceptionNotMatchingIps);
            resultMap.put("ipv4_address_denied", ipv4Denied);
            resultMap.put("ipv6_address_allowed", ipv6Allowed);
            resultMap.put("ipv6_address_denied", ipv6Denied);

            if (!matchedIps.isEmpty()) {
                resultMap.put("matches", true);
                resultMap.put("matchType", "ip_subnet_match");
                resultMap.put("matchedWith", "direct_subnet_list");
                resultMap.put("reason", "IPs found in subnet_list");
            } else if (!exceptionMatchingIps.isEmpty()) {
                resultMap.put("matches", true);
                resultMap.put("matchType", "exception_IP_matched");
                resultMap.put("matchedWith", "direct_subnet_list");
                resultMap.put("reason", "Exception IPs found in subnet_list");
            } else {
                resultMap.put("reason", "Secured node uses subnet_list, unresolved VMs not evaluated");
            }

            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                matchedIps,
                ipv6Allowed
            ));
            return resultMap;
        }

        boolean hasSubnetCategories = !securedSubnetCategories.isEmpty() && !securedSubnetCategories.contains("any");
        boolean hasVmCategories = !securedVmCategories.isEmpty() && !securedVmCategories.contains("any");

        if (!hasSubnetCategories && !hasVmCategories) {
            resultMap.put("reason", "Secured node has no category requirements or uses 'any'");
            resultMap.put("matchedIps", filterIpsByProtocol(filteredIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal));
            resultMap.put("exception_matching_ips", filterExceptionMatches(filteredIps,
                extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
            if (!ipv6Only && isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_allowed", filterIpv6Addresses(filteredIps));
            }
            if (!ipv6Only && !isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_denied", filterIpv6Addresses(filteredIps));
            }
            if (!ipv4Only) {
                resultMap.put("ipv4_address_denied", filterIpv4Addresses(filteredIps));
            }
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        boolean subnetMatch = hasSubnetCategories && isSubsetOf(securedSubnetCategories, subnetCategories);
        boolean vmMatch = hasVmCategories && isSubsetOf(securedVmCategories, vmCategories);

        if ((hasSubnetCategories && hasVmCategories && subnetMatch && vmMatch) ||
            (hasSubnetCategories && !hasVmCategories && subnetMatch) ||
            (!hasSubnetCategories && hasVmCategories && vmMatch)) {
            resultMap.put("reason", "VM is resolved: all required categories match");
            resultMap.put("matchedIps", filterIpsByProtocol(filteredIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal));
            resultMap.put("exception_matching_ips", filterExceptionMatches(filteredIps,
                extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
            if (!ipv6Only && isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_allowed", filterIpv6Addresses(filteredIps));
            }
            if (!ipv6Only && !isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_denied", filterIpv6Addresses(filteredIps));
            }
            if (!ipv4Only) {
                resultMap.put("ipv4_address_denied", filterIpv4Addresses(filteredIps));
            }
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        resultMap.put("isUnresolved", true);

        if ((!hasSubnetCategories || !subnetMatch) && (!hasVmCategories || !vmMatch)) {
            resultMap.put("scenario", "no_category_match");
            resultMap.put("priority", 1);
            resultMap.put("reason", "No categories match: VM and subnet do not satisfy secured node requirements");
            resultMap.put("matchedIps", filterIpsByProtocol(filteredIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal));
            resultMap.put("exception_matching_ips", filterExceptionMatches(filteredIps,
                extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
            if (!ipv6Only && isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_allowed", filterIpv6Addresses(filteredIps));
            }
            if (!ipv6Only && !isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_denied", filterIpv6Addresses(filteredIps));
            }
            if (!ipv4Only) {
                resultMap.put("ipv4_address_denied", filterIpv4Addresses(filteredIps));
            }
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        if (!hasSubnetCategories || (hasVmCategories && vmMatch && !subnetMatch)) {
            resultMap.put("scenario", "only_vm_categories_match");
            resultMap.put("priority", 3);
            resultMap.put("reason", "Only VM categories match: subnet categories do not satisfy secured node requirements");
            resultMap.put("matchedIps", filterIpsByProtocol(filteredIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal));
            resultMap.put("exception_matching_ips", filterExceptionMatches(filteredIps,
                extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
            if (!ipv6Only && isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_allowed", filterIpv6Addresses(filteredIps));
            }
            if (!ipv6Only && !isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_denied", filterIpv6Addresses(filteredIps));
            }
            if (!ipv4Only) {
                resultMap.put("ipv4_address_denied", filterIpv4Addresses(filteredIps));
            }
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        if (!hasVmCategories || (hasSubnetCategories && subnetMatch && !vmMatch)) {
            resultMap.put("scenario", "only_subnet_categories_match");
            resultMap.put("priority", 4);
            resultMap.put("reason", "Only subnet categories match: VM categories do not satisfy secured node requirements");
            resultMap.put("matchedIps", filterIpsByProtocol(filteredIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal));
            resultMap.put("exception_matching_ips", filterExceptionMatches(filteredIps,
                extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
            if (!ipv6Only && isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_allowed", filterIpv6Addresses(filteredIps));
            }
            if (!ipv6Only && !isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_denied", filterIpv6Addresses(filteredIps));
            }
            if (!ipv4Only) {
                resultMap.put("ipv4_address_denied", filterIpv4Addresses(filteredIps));
            }
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        Set<String> vmCategorySet = new HashSet<>(vmCategories);
        Set<String> securedVmCategorySet = new HashSet<>(securedVmCategories);
        Set<String> subnetCategorySet = new HashSet<>(subnetCategories);
        Set<String> securedSubnetCategorySet = new HashSet<>(securedSubnetCategories);

        boolean partialVmMatch = hasVmCategories && !vmMatch &&
            !Collections.disjoint(vmCategorySet, securedVmCategorySet);
        boolean partialSubnetMatch = hasSubnetCategories && !subnetMatch &&
            !Collections.disjoint(subnetCategorySet, securedSubnetCategorySet);

        if (partialVmMatch || partialSubnetMatch) {
            resultMap.put("scenario", "partial_category_match");
            resultMap.put("priority", 2);
            resultMap.put("reason", "Partial category match: some VM or subnet categories match, but not all");
            resultMap.put("partialVmMatch", partialVmMatch);
            resultMap.put("partialSubnetMatch", partialSubnetMatch);
            resultMap.put("matchedIps", filterIpsByProtocol(filteredIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal));
            resultMap.put("exception_matching_ips", filterExceptionMatches(filteredIps,
                extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
            if (!ipv6Only && isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_allowed", filterIpv6Addresses(filteredIps));
            }
            if (!ipv6Only && !isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_denied", filterIpv6Addresses(filteredIps));
            }
            if (!ipv4Only) {
                resultMap.put("ipv4_address_denied", filterIpv4Addresses(filteredIps));
            }
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        resultMap.put("reason", "Unresolved VM, but no specific scenario identified");
        resultMap.put("matchedIps", filterIpsByProtocol(filteredIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal));
        resultMap.put("exception_matching_ips", filterExceptionMatches(filteredIps,
            extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
        if (!ipv6Only && isIpv6TrafficAllowed) {
            resultMap.put("ipv6_address_allowed", filterIpv6Addresses(filteredIps));
        }
        if (!ipv6Only && !isIpv6TrafficAllowed) {
            resultMap.put("ipv6_address_denied", filterIpv6Addresses(filteredIps));
        }
        if (!ipv4Only) {
            resultMap.put("ipv4_address_denied", filterIpv4Addresses(filteredIps));
        }
        resultMap.put("unmatchedIps", computeUnmatchedIps(
            learnedIps,
            virtualIps,
            (List<String>) resultMap.get("matchedIps"),
            (List<String>) resultMap.get("ipv6_address_allowed")
        ));
        return resultMap;
    }

    /**
     * Helper method to expand port specifications into individual ports and store match reasons.
     */
    private void expandPorts(List<String> portSpecs, Set<Integer> expandedPorts, Map<Integer, String> portToMatchReason) {
        if (portSpecs == null) return;

        for (String portSpec : portSpecs) {
            if (portSpec == null) continue;
            if (portSpec.contains("-")) {
                String[] range = portSpec.split("-");
                try {
                    int start = Integer.parseInt(range[0]);
                    int end = Integer.parseInt(range[1]);
                    for (int port = start; port <= end; port++) {
                        expandedPorts.add(port);
                        portToMatchReason.put(port, "range_match:" + portSpec);
                    }
                } catch (NumberFormatException e) {
                    continue;
                }
            } else {
                try {
                    int port = Integer.parseInt(portSpec);
                    expandedPorts.add(port);
                    portToMatchReason.put(port, "exact_match:" + portSpec);
                } catch (NumberFormatException e) {
                    continue;
                }
            }
        }
    }

    /**
     * Optimized helper function that uses set operations to efficiently check port matches.
     */
    private Map<String, Object> isServiceGroupMatchWithDetails(
            Node serviceGroupNode,
            List<String> tcpPorts,
            List<String> udpPorts,
            List<String> icmpTypes) {

        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("matches", true);

        if (serviceGroupNode == null) {
            resultMap.put("matches", false);
            resultMap.put("reason", "Service group node is null");
            return resultMap;
        }

        List<String> sgTcpPorts = extractPropertyAsList(serviceGroupNode, "tcp");
        List<String> sgUdpPorts = extractPropertyAsList(serviceGroupNode, "udp");
        List<String> sgIcmpTypes = extractPropertyAsList(serviceGroupNode, "icmp");

        resultMap.put("sgTcpPorts", new ArrayList<>(sgTcpPorts));
        resultMap.put("sgUdpPorts", new ArrayList<>(sgUdpPorts));
        resultMap.put("sgIcmpTypes", new ArrayList<>(sgIcmpTypes));

        Map<String, String> tcpMatches = new HashMap<>();
        Map<String, String> udpMatches = new HashMap<>();
        Map<String, String> icmpMatches = new HashMap<>();

        if (tcpPorts != null && !tcpPorts.isEmpty()) {
            if (sgTcpPorts.contains("all")) {
                for (String port : tcpPorts) {
                    if (port != null) {
                        tcpMatches.put(port, "all_match");
                    }
                }
            } else {
                Set<Integer> userPortsExpanded = new HashSet<>();
                Map<Integer, String> userPortToOriginal = new HashMap<>();

                for (String portSpec : tcpPorts) {
                    if (portSpec == null) continue;
                    if (portSpec.contains("-")) {
                        String[] range = portSpec.split("-");
                        try {
                            int start = Integer.parseInt(range[0]);
                            int end = Integer.parseInt(range[1]);
                            for (int port = start; port <= end; port++) {
                                userPortsExpanded.add(port);
                                userPortToOriginal.put(port, portSpec);
                            }
                        } catch (NumberFormatException e) {
                            continue;
                        }
                    } else {
                        try {
                            int port = Integer.parseInt(portSpec);
                            userPortsExpanded.add(port);
                            userPortToOriginal.put(port, portSpec);
                        } catch (NumberFormatException e) {
                            continue;
                        }
                    }
                }

                Set<Integer> sgPortsExpanded = new HashSet<>();
                Map<Integer, String> portToMatchReason = new HashMap<>();
                expandPorts(sgTcpPorts, sgPortsExpanded, portToMatchReason);

                Set<Integer> matchingPorts = new HashSet<>(userPortsExpanded);
                matchingPorts.retainAll(sgPortsExpanded);

                Set<Integer> nonMatchingPorts = new HashSet<>(userPortsExpanded);
                nonMatchingPorts.removeAll(sgPortsExpanded);

                Map<String, Set<Integer>> matchesByOriginalSpec = new HashMap<>();

                for (Integer port : matchingPorts) {
                    String origSpec = userPortToOriginal.get(port);
                    matchesByOriginalSpec.computeIfAbsent(origSpec, k -> new HashSet<>()).add(port);
                }

                for (Map.Entry<String, Set<Integer>> entry : matchesByOriginalSpec.entrySet()) {
                    String origSpec = entry.getKey();
                    Set<Integer> matchedPorts = entry.getValue();

                    if (origSpec.contains("-")) {
                        String[] range = origSpec.split("-");
                        int start = Integer.parseInt(range[0]);
                        int end = Integer.parseInt(range[1]);
                        int expectedSize = end - start + 1;

                        if (matchedPorts.size() == expectedSize) {
                            String bestMatch = findBestContainingRange(start, end, sgTcpPorts);
                            tcpMatches.put(origSpec, bestMatch != null ?
                                    "contained_in_range:" + bestMatch : "multiple_matches");
                        } else {
                            tcpMatches.put(origSpec, "partial_match");
                            resultMap.put("matches", false);
                            resultMap.put("failedOn", "tcp:" + origSpec);
                        }
                    } else {
                        int port = Integer.parseInt(origSpec);
                        tcpMatches.put(origSpec, portToMatchReason.get(port));
                    }
                }

                for (Integer port : nonMatchingPorts) {
                    String origSpec = userPortToOriginal.get(port);
                    if (!tcpMatches.containsKey(origSpec)) {
                        tcpMatches.put(origSpec, "no_match");
                        resultMap.put("matches", false);
                        resultMap.put("failedOn", "tcp:" + origSpec);
                    }
                }
            }
        }

        if (udpPorts != null && !udpPorts.isEmpty()) {
            if (sgUdpPorts.contains("all")) {
                for (String port : udpPorts) {
                    if (port != null) {
                        udpMatches.put(port, "all_match");
                    }
                }
            } else {
                Set<Integer> userPortsExpanded = new HashSet<>();
                Map<Integer, String> userPortToOriginal = new HashMap<>();

                for (String portSpec : udpPorts) {
                    if (portSpec == null) continue;
                    if (portSpec.contains("-")) {
                        String[] range = portSpec.split("-");
                        try {
                            int start = Integer.parseInt(range[0]);
                            int end = Integer.parseInt(range[1]);
                            for (int port = start; port <= end; port++) {
                                userPortsExpanded.add(port);
                                userPortToOriginal.put(port, portSpec);
                            }
                        } catch (NumberFormatException e) {
                            continue;
                        }
                    } else {
                        try {
                            int port = Integer.parseInt(portSpec);
                            userPortsExpanded.add(port);
                            userPortToOriginal.put(port, portSpec);
                        } catch (NumberFormatException e) {
                            continue;
                        }
                    }
                }

                Set<Integer> sgPortsExpanded = new HashSet<>();
                Map<Integer, String> portToMatchReason = new HashMap<>();
                expandPorts(sgUdpPorts, sgPortsExpanded, portToMatchReason);

                Set<Integer> matchingPorts = new HashSet<>(userPortsExpanded);
                matchingPorts.retainAll(sgPortsExpanded);

                Set<Integer> nonMatchingPorts = new HashSet<>(userPortsExpanded);
                nonMatchingPorts.removeAll(sgPortsExpanded);

                Map<String, Set<Integer>> matchesByOriginalSpec = new HashMap<>();

                for (Integer port : matchingPorts) {
                    String origSpec = userPortToOriginal.get(port);
                    matchesByOriginalSpec.computeIfAbsent(origSpec, k -> new HashSet<>()).add(port);
                }

                for (Map.Entry<String, Set<Integer>> entry : matchesByOriginalSpec.entrySet()) {
                    String origSpec = entry.getKey();
                    Set<Integer> matchedPorts = entry.getValue();

                    if (origSpec.contains("-")) {
                        String[] range = origSpec.split("-");
                        int start = Integer.parseInt(range[0]);
                        int end = Integer.parseInt(range[1]);
                        int expectedSize = end - start + 1;

                        if (matchedPorts.size() == expectedSize) {
                            String bestMatch = findBestContainingRange(start, end, sgUdpPorts);
                            udpMatches.put(origSpec, bestMatch != null ?
                                    "contained_in_range:" + bestMatch : "multiple_matches");
                        } else {
                            udpMatches.put(origSpec, "partial_match");
                            resultMap.put("matches", false);
                            resultMap.put("failedOn", "udp:" + origSpec);
                        }
                    } else {
                        int port = Integer.parseInt(origSpec);
                        udpMatches.put(origSpec, portToMatchReason.get(port));
                    }
                }

                for (Integer port : nonMatchingPorts) {
                    String origSpec = userPortToOriginal.get(port);
                    if (!udpMatches.containsKey(origSpec)) {
                        udpMatches.put(origSpec, "no_match");
                        resultMap.put("matches", false);
                        resultMap.put("failedOn", "udp:" + origSpec);
                    }
                }
            }
        }

        if (icmpTypes != null && !icmpTypes.isEmpty()) {
            if (sgIcmpTypes.contains("all") || sgIcmpTypes.contains("any:any")) {
                for (String type : icmpTypes) {
                    if (type != null) {
                        icmpMatches.put(type, "all_match");
                    }
                }
            } else {
                Set<String> exactMatches = new HashSet<>(sgIcmpTypes);

                Map<String, Set<String>> typeToWildcards = new HashMap<>();
                Map<String, Set<String>> codeToWildcards = new HashMap<>();

                for (String sgType : sgIcmpTypes) {
                    if (sgType == null) continue;
                    String[] parts = sgType.split(":");
                    if (parts.length == 2) {
                        String type = parts[0];
                        String code = parts[1];

                        if (code.equals("any")) {
                            typeToWildcards.computeIfAbsent(type, k -> new HashSet<>()).add(sgType);
                        } else if (type.equals("any")) {
                            codeToWildcards.computeIfAbsent(code, k -> new HashSet<>()).add(sgType);
                        }
                    }
                }

                for (String icmpType : icmpTypes) {
                    if (icmpType == null) continue;
                    if (exactMatches.contains(icmpType)) {
                        icmpMatches.put(icmpType, "exact_match:" + icmpType);
                        continue;
                    }

                    boolean matched = false;
                    String[] parts = icmpType.split(":");
                    if (parts.length == 2) {
                        String type = parts[0];
                        String code = parts[1];

                        if (typeToWildcards.containsKey(type)) {
                            String wildcard = typeToWildcards.get(type).iterator().next();
                            icmpMatches.put(icmpType, "wildcard_match:" + wildcard);
                            matched = true;
                        } else if (codeToWildcards.containsKey(code)) {
                            String wildcard = codeToWildcards.get(code).iterator().next();
                            icmpMatches.put(icmpType, "wildcard_match:" + wildcard);
                            matched = true;
                        }
                    }

                    if (!matched) {
                        icmpMatches.put(icmpType, "no_match");
                        resultMap.put("matches", false);
                        resultMap.put("failedOn", "icmp:" + icmpType);
                    }
                }
            }
        }

        resultMap.put("tcpMatches", tcpMatches);
        resultMap.put("udpMatches", udpMatches);
        resultMap.put("icmpMatches", icmpMatches);

        return resultMap;
    }

    /**
     * Helper method to find the smallest range in the service group that contains the user range.
     */
    private String findBestContainingRange(int userStart, int userEnd, List<String> sgPorts) {
        String bestMatch = null;
        int smallestRangeSize = Integer.MAX_VALUE;

        for (String sgPort : sgPorts) {
            if (sgPort == null) continue;
            if (sgPort.contains("-")) {
                String[] range = sgPort.split("-");
                try {
                    int sgStart = Integer.parseInt(range[0]);
                    int sgEnd = Integer.parseInt(range[1]);

                    if (sgStart <= userStart && sgEnd >= userEnd) {
                        int rangeSize = sgEnd - sgStart;
                        if (rangeSize < smallestRangeSize) {
                            smallestRangeSize = rangeSize;
                            bestMatch = sgPort;
                        }
                    }
                } catch (NumberFormatException e) {
                    continue;
                }
            }
        }

        return bestMatch;
    }

    /**
     * Helper function to check if one list is a subset of another.
     */
    private boolean isSubsetOf(List<String> subset, List<String> superset) {
        if (subset == null || superset == null || subset.isEmpty()) {
            return false;
        }
        return superset.containsAll(subset);
    }

    /**
     * Helper method to compute the union of two lists, removing duplicates.
     */
    private List<String> union(List<String> list1, List<String> list2) {
        Set<String> set = new HashSet<>();
        set.addAll(list1);
        set.addAll(list2);
        return new ArrayList<>(set);
    }
}

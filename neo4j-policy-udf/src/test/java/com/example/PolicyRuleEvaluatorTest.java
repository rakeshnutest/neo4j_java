import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.neo4j.graphdb.Node;
import org.neo4j.graphdb.Relationship;

import java.util.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class PolicyRuleEvaluatorTest {

    private final PolicyRuleEvaluator evaluator = new PolicyRuleEvaluator();

    @Mock
    private Node securedNode;

    @Mock
    private Node subnetNode;

    @Mock
    private Relationship interfaceRel;

    @Mock
    private Node vmNode;

    @Mock
    private Node serviceGroupNode;

    // Tests for evaluateSecurityRule
    @Test
    public void testEvaluateSecurityRule_WithAllNullPropertiesOnSecuredNode() {
        // Stub all hasProperty calls that might be invoked
        when(securedNode.hasProperty("subnet_list")).thenReturn(false);
        when(securedNode.hasProperty("subnet_category_name")).thenReturn(false);
        when(securedNode.hasProperty("vm_category_name")).thenReturn(false);
        
        when(interfaceRel.hasProperty("learned_ips")).thenReturn(true);
        when(interfaceRel.getProperty("learned_ips")).thenReturn(new String[]{"192.168.1.5"});
        
        when(subnetNode.hasProperty("subnet_category_name")).thenReturn(true);
        when(subnetNode.getProperty("subnet_category_name")).thenReturn(new String[]{"internal"});
        
        when(vmNode.hasProperty("vm_category_name")).thenReturn(true);
        when(vmNode.getProperty("vm_category_name")).thenReturn(new String[]{"web"});
        
        Map<String, Object> result = evaluator.evaluateSecurityRule(securedNode, subnetNode, interfaceRel, vmNode);
        
        assertFalse((Boolean) result.get("matches"));
        assertEquals("none", result.get("matchType"));
        assertEquals("All secured node properties are null; no criteria to evaluate", result.get("reason"));
    }

    @Test
    public void testEvaluateSecurityRule_WithNullLearnedIps() {
        // We don't actually need to stub anything about subnet_list here
        // since the method returns early when no learned IPs are found
        when(interfaceRel.hasProperty("learned_ips")).thenReturn(false);
        
        Map<String, Object> result = evaluator.evaluateSecurityRule(securedNode, subnetNode, interfaceRel, vmNode);
        
        assertFalse((Boolean) result.get("matches"));
        assertEquals("none", result.get("matchType"));
        assertEquals("No learned IPs found on interface", result.get("reason"));
    }

    @Test
    public void testEvaluateSecurityRule_WithNullNodes() {
        Map<String, Object> result = evaluator.evaluateSecurityRule(null, subnetNode, interfaceRel, vmNode);
        
        assertFalse((Boolean) result.get("matches"));
        assertEquals("none", result.get("matchType"));
        assertTrue(((String) result.get("reason")).contains("securedNode=true"));
    }

    @Test
    public void testEvaluateSecurityRule_WithNullSubnetNode() {
        // We don't need to stub securedNode or interfaceRel here as they'll never be accessed
        Map<String, Object> result = evaluator.evaluateSecurityRule(securedNode, null, interfaceRel, vmNode);
        
        assertFalse((Boolean) result.get("matches"));
        assertEquals("none", result.get("matchType"));
        assertTrue(((String) result.get("reason")).contains("subnetNode=true"));
    }

    @Test
    public void testEvaluateSecurityRule_WithNullInterfaceRel() {
        // We don't need to stub securedNode here as it'll never be accessed
        Map<String, Object> result = evaluator.evaluateSecurityRule(securedNode, subnetNode, null, vmNode);
        
        assertFalse((Boolean) result.get("matches"));
        assertEquals("none", result.get("matchType"));
        assertTrue(((String) result.get("reason")).contains("interfaceRel=true"));
    }

    @Test
    public void testEvaluateSecurityRule_WithNullVMNode() {
        // We don't need to stub securedNode or interfaceRel here as they'll never be accessed 
        Map<String, Object> result = evaluator.evaluateSecurityRule(securedNode, subnetNode, interfaceRel, null);
        
        assertFalse((Boolean) result.get("matches"));
        assertEquals("none", result.get("matchType"));
        assertTrue(((String) result.get("reason")).contains("vmNode=true"));
    }

    @Test
    public void testEvaluateSecurityRule_WithLearnedIpsAsList() {
        when(securedNode.hasProperty("subnet_list")).thenReturn(true);
        when(securedNode.getProperty("subnet_list")).thenReturn(new String[]{"192.168.1.0/24"});
        when(securedNode.hasProperty("subnet_category_name")).thenReturn(false);
        when(securedNode.hasProperty("vm_category_name")).thenReturn(false);
        
        when(interfaceRel.hasProperty("learned_ips")).thenReturn(true);
        when(interfaceRel.getProperty("learned_ips")).thenReturn(new String[]{"192.168.1.5"});
        
        // These stubs aren't actually needed for this test since the subnet_list match short-circuits
        // the evaluation before checking categories
        
        Map<String, Object> result = evaluator.evaluateSecurityRule(securedNode, subnetNode, interfaceRel, vmNode);
        
        assertTrue((Boolean) result.get("matches"));
        assertEquals("ip_subnet_match", result.get("matchType"));
        assertTrue(((List<String>) result.get("matchedIps")).contains("192.168.1.5"));
    }

    @Test
    public void testEvaluateSecurityRule_WithLearnedIpsAsSingleString() {
        when(securedNode.hasProperty("subnet_list")).thenReturn(true);
        when(securedNode.getProperty("subnet_list")).thenReturn(new String[]{"192.168.1.0/24"});
        when(securedNode.hasProperty("subnet_category_name")).thenReturn(false);
        when(securedNode.hasProperty("vm_category_name")).thenReturn(false);
        
        when(interfaceRel.hasProperty("learned_ips")).thenReturn(true);
        when(interfaceRel.getProperty("learned_ips")).thenReturn("192.168.1.5");
        
        // These stubs aren't actually needed for this test since the subnet_list match short-circuits
        // the evaluation before checking categories
        
        Map<String, Object> result = evaluator.evaluateSecurityRule(securedNode, subnetNode, interfaceRel, vmNode);
        
        assertTrue((Boolean) result.get("matches"));
        assertEquals("ip_subnet_match", result.get("matchType"));
        assertTrue(((List<String>) result.get("matchedIps")).contains("192.168.1.5"));
    }

    @Test
    public void testEvaluateSecurityRule_WithAnyAnyCategories() {
        when(securedNode.hasProperty("subnet_list")).thenReturn(false);
        when(securedNode.hasProperty("subnet_category_name")).thenReturn(true);
        when(securedNode.getProperty("subnet_category_name")).thenReturn(new String[]{"any"});
        when(securedNode.hasProperty("vm_category_name")).thenReturn(true);
        when(securedNode.getProperty("vm_category_name")).thenReturn(new String[]{"any"});
        
        when(interfaceRel.hasProperty("learned_ips")).thenReturn(true);
        when(interfaceRel.getProperty("learned_ips")).thenReturn(new String[]{"192.168.1.5"});
        
        Map<String, Object> result = evaluator.evaluateSecurityRule(securedNode, subnetNode, interfaceRel, vmNode);
        
        assertTrue((Boolean) result.get("matches"));
        assertEquals("any_any_match", result.get("matchType"));
        assertTrue(((List<String>) result.get("matchedIps")).contains("192.168.1.5"));
    }

    @Test
    public void testEvaluateSecurityRule_WithCategoryMatch() {
        when(securedNode.hasProperty("subnet_list")).thenReturn(false);
        when(securedNode.hasProperty("subnet_category_name")).thenReturn(true);
        when(securedNode.getProperty("subnet_category_name")).thenReturn(new String[]{"internal"});
        when(securedNode.hasProperty("vm_category_name")).thenReturn(true);
        when(securedNode.getProperty("vm_category_name")).thenReturn(new String[]{"web"});
        
        when(interfaceRel.hasProperty("learned_ips")).thenReturn(true);
        when(interfaceRel.getProperty("learned_ips")).thenReturn(new String[]{"192.168.1.5"});
        
        when(subnetNode.hasProperty("subnet_category_name")).thenReturn(true);
        when(subnetNode.getProperty("subnet_category_name")).thenReturn(new String[]{"internal"});
        
        when(vmNode.hasProperty("vm_category_name")).thenReturn(true);
        when(vmNode.getProperty("vm_category_name")).thenReturn(new String[]{"web"});
        
        Map<String, Object> result = evaluator.evaluateSecurityRule(securedNode, subnetNode, interfaceRel, vmNode);
        
        assertTrue((Boolean) result.get("matches"));
        assertEquals("subnet_and_vm_category_match", result.get("matchType"));
        assertTrue(((List<String>) result.get("matchedIps")).contains("192.168.1.5"));
    }

    // Tests for isIpInSubnetList
    @Test
    public void testIsIpInSubnetList_WithMatchingIPv4Subnet() {
        boolean result = evaluator.isIpInSubnetList("192.168.1.5", Arrays.asList("192.168.1.0/24"));
        assertTrue(result);
    }

    @Test
    public void testIsIpInSubnetList_WithNonMatchingIPv4Subnet() {
        boolean result = evaluator.isIpInSubnetList("192.168.2.5", Arrays.asList("192.168.1.0/24"));
        assertFalse(result);
    }

    @Test
    public void testIsIpInSubnetList_WithExactIpMatch() {
        boolean result = evaluator.isIpInSubnetList("192.168.1.5", Arrays.asList("192.168.1.5"));
        assertTrue(result);
    }

    @Test
    public void testIsIpInSubnetList_WithNullIp() {
        boolean result = evaluator.isIpInSubnetList(null, Arrays.asList("192.168.1.0/24"));
        assertFalse(result);
    }

    @Test
    public void testIsIpInSubnetList_WithNullSubnetList() {
        boolean result = evaluator.isIpInSubnetList("192.168.1.5", null);
        assertFalse(result);
    }

    @Test
    public void testIsIpInSubnetList_WithIPv6Subnet() {
        boolean result = evaluator.isIpInSubnetList("2001:db8::1", Arrays.asList("2001:db8::/32"));
        assertTrue(result);
    }

    // Tests for evaluateSecurityRuleByVmName
    @Test
    public void testEvaluateSecurityRuleByVmName_WithMatchingVmName() {
        when(securedNode.hasProperty("subnet_list")).thenReturn(true);
        when(securedNode.getProperty("subnet_list")).thenReturn(new String[]{"192.168.1.0/24"});
        when(securedNode.hasProperty("subnet_category_name")).thenReturn(false);
        when(securedNode.hasProperty("vm_category_name")).thenReturn(false);
        
        when(interfaceRel.hasProperty("learned_ips")).thenReturn(true);
        when(interfaceRel.getProperty("learned_ips")).thenReturn(new String[]{"192.168.1.5"});
        
        when(vmNode.hasProperty("name")).thenReturn(true);
        when(vmNode.getProperty("name")).thenReturn("vm1");
        
        List<String> vmNamesToMatch = Arrays.asList("vm1");
        
        Map<String, Object> result = evaluator.evaluateSecurityRuleByVmName(
                securedNode, subnetNode, interfaceRel, vmNode, vmNamesToMatch);
        
        assertTrue((Boolean) result.get("matches"));
        assertEquals("ip_subnet_match", result.get("matchType"));
        assertTrue(((List<String>) result.get("matchedVmNames")).contains("vm1"));
    }

    @Test
    public void testEvaluateSecurityRuleByVmName_WithNonMatchingVmName() {
        when(vmNode.hasProperty("name")).thenReturn(true);
        when(vmNode.getProperty("name")).thenReturn("vm2");
        
        List<String> vmNamesToMatch = Arrays.asList("vm1");
        
        Map<String, Object> result = evaluator.evaluateSecurityRuleByVmName(
                securedNode, subnetNode, interfaceRel, vmNode, vmNamesToMatch);
        
        assertFalse((Boolean) result.get("matches"));
        assertEquals("none", result.get("matchType"));
        assertEquals("VM name doesn't match", result.get("reason"));
    }

    // Tests for evaluateSecurityRuleByIp
    @Test
    public void testEvaluateSecurityRuleByIp_WithMatchingIp() {
        when(securedNode.hasProperty("subnet_list")).thenReturn(true);
        when(securedNode.getProperty("subnet_list")).thenReturn(new String[]{"192.168.1.0/24"});
        // Removed unnecessary category stubbings
        
        when(interfaceRel.hasProperty("learned_ips")).thenReturn(true);
        when(interfaceRel.getProperty("learned_ips")).thenReturn(new String[]{"192.168.1.5"});
        
        List<String> ipsToMatch = Arrays.asList("192.168.1.5");
        
        Map<String, Object> result = evaluator.evaluateSecurityRuleByIp(
                securedNode, subnetNode, interfaceRel, vmNode, ipsToMatch);
        
        assertTrue((Boolean) result.get("matches"));
        assertEquals("ip_subnet_match", result.get("matchType"));
        assertTrue(((List<String>) result.get("matchedIps")).contains("192.168.1.5"));
    }

    @Test
    public void testEvaluateSecurityRuleByIp_WithNonMatchingIp() {
        when(interfaceRel.hasProperty("learned_ips")).thenReturn(true);
        when(interfaceRel.getProperty("learned_ips")).thenReturn(new String[]{"192.168.1.5"});
        
        List<String> ipsToMatch = Arrays.asList("192.168.2.5");
        
        Map<String, Object> result = evaluator.evaluateSecurityRuleByIp(
                securedNode, subnetNode, interfaceRel, vmNode, ipsToMatch);
        
        assertFalse((Boolean) result.get("matches"));
        assertEquals("none", result.get("matchType"));
        assertEquals("Specified IPs not found in interface's learned IPs", result.get("reason"));
    }

    // Tests for evaluateSecurityRuleByIpSG
    @Test
    public void testEvaluateSecurityRuleByIpSG_WithMatchingIpAndPorts() {
        when(securedNode.hasProperty("subnet_list")).thenReturn(true);
        when(securedNode.getProperty("subnet_list")).thenReturn(new String[]{"192.168.1.0/24"});
        // Removed unnecessary stubs for subnet_category_name and vm_category_name
        
        when(interfaceRel.hasProperty("learned_ips")).thenReturn(true);
        when(interfaceRel.getProperty("learned_ips")).thenReturn(new String[]{"192.168.1.5"});
        
        when(serviceGroupNode.hasProperty("tcp")).thenReturn(true);
        when(serviceGroupNode.getProperty("tcp")).thenReturn(new String[]{"80"});
        when(serviceGroupNode.hasProperty("udp")).thenReturn(false);
        when(serviceGroupNode.hasProperty("icmp")).thenReturn(false);
        
        List<String> ipsToMatch = Arrays.asList("192.168.1.5");
        List<String> tcpPorts = Arrays.asList("80");
        List<String> udpPorts = Collections.emptyList();
        List<String> icmpTypes = Collections.emptyList();
        
        Map<String, Object> result = evaluator.evaluateSecurityRuleByIpSG(
                securedNode, subnetNode, interfaceRel, vmNode, serviceGroupNode,
                ipsToMatch, tcpPorts, udpPorts, icmpTypes);
        
        assertTrue((Boolean) result.get("matches"));
        assertEquals("ip_subnet_match", result.get("matchType"));
        assertTrue(((List<String>) result.get("matchedIps")).contains("192.168.1.5"));
        assertTrue((Boolean) result.get("serviceGroupMatched"));
    }

    @Test
    public void testEvaluateSecurityRuleByIpSG_WithNonMatchingPorts() {
        // We only need to mock the service group node for this test
        // since the method will return early due to port mismatch
        when(serviceGroupNode.hasProperty("tcp")).thenReturn(true);
        when(serviceGroupNode.getProperty("tcp")).thenReturn(new String[]{"80"});
        when(serviceGroupNode.hasProperty("udp")).thenReturn(false);
        when(serviceGroupNode.hasProperty("icmp")).thenReturn(false);
        
        List<String> ipsToMatch = Arrays.asList("192.168.1.5");
        List<String> tcpPorts = Arrays.asList("443");
        List<String> udpPorts = Collections.emptyList();
        List<String> icmpTypes = Collections.emptyList();
        
        Map<String, Object> result = evaluator.evaluateSecurityRuleByIpSG(
                securedNode, subnetNode, interfaceRel, vmNode, serviceGroupNode,
                ipsToMatch, tcpPorts, udpPorts, icmpTypes);
        
        assertFalse((Boolean) result.get("matches"));
        assertEquals("none", result.get("matchType"));
        assertEquals("Service group mismatch", result.get("reason"));
    }

    // Tests for evaluateSecurityRuleByVmNameSG
    @Test
    public void testEvaluateSecurityRuleByVmNameSG_WithMatchingVmNameAndPorts() {
        when(securedNode.hasProperty("subnet_list")).thenReturn(true);
        when(securedNode.getProperty("subnet_list")).thenReturn(new String[]{"192.168.1.0/24"});
        when(securedNode.hasProperty("subnet_category_name")).thenReturn(false);
        when(securedNode.hasProperty("vm_category_name")).thenReturn(false);
        
        when(interfaceRel.hasProperty("learned_ips")).thenReturn(true);
        when(interfaceRel.getProperty("learned_ips")).thenReturn(new String[]{"192.168.1.5"});
        
        when(vmNode.hasProperty("name")).thenReturn(true);
        when(vmNode.getProperty("name")).thenReturn("vm1");
        
        when(serviceGroupNode.hasProperty("tcp")).thenReturn(true);
        when(serviceGroupNode.getProperty("tcp")).thenReturn(new String[]{"80"});
        when(serviceGroupNode.hasProperty("udp")).thenReturn(false);
        when(serviceGroupNode.hasProperty("icmp")).thenReturn(false);
        
        List<String> vmNamesToMatch = Arrays.asList("vm1");
        List<String> tcpPorts = Arrays.asList("80");
        List<String> udpPorts = Collections.emptyList();
        List<String> icmpTypes = Collections.emptyList();
        
        Map<String, Object> result = evaluator.evaluateSecurityRuleByVmNameSG(
                securedNode, subnetNode, interfaceRel, vmNode, serviceGroupNode,
                vmNamesToMatch, tcpPorts, udpPorts, icmpTypes);
        
        assertTrue((Boolean) result.get("matches"));
        assertEquals("ip_subnet_match", result.get("matchType"));
        assertTrue(((List<String>) result.get("matchedVmNames")).contains("vm1"));
        assertTrue((Boolean) result.get("serviceGroupMatched"));
    }

    @Test
    public void testEvaluateSecurityRuleByVmNameSG_WithNonMatchingVmName() {
        when(vmNode.hasProperty("name")).thenReturn(true);
        when(vmNode.getProperty("name")).thenReturn("vm2");
        
        when(serviceGroupNode.hasProperty("tcp")).thenReturn(true);
        when(serviceGroupNode.getProperty("tcp")).thenReturn(new String[]{"80"});
        when(serviceGroupNode.hasProperty("udp")).thenReturn(false);
        when(serviceGroupNode.hasProperty("icmp")).thenReturn(false);
        
        List<String> vmNamesToMatch = Arrays.asList("vm1");
        List<String> tcpPorts = Arrays.asList("80");
        List<String> udpPorts = Collections.emptyList();
        List<String> icmpTypes = Collections.emptyList();
        
        Map<String, Object> result = evaluator.evaluateSecurityRuleByVmNameSG(
                securedNode, subnetNode, interfaceRel, vmNode, serviceGroupNode,
                vmNamesToMatch, tcpPorts, udpPorts, icmpTypes);
        
        assertFalse((Boolean) result.get("matches"));
        assertEquals("none", result.get("matchType"));
        assertEquals("VM name doesn't match", result.get("reason"));
    }
}

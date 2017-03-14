/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package RGSDigestTools;

import SignatureTESTS.NewClass;
import java.security.UnrecoverableEntryException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author p.chavdarov
 */
public class SignatureToolTest {
    
    public SignatureToolTest() {
    }
    /**
     * Test of bytesToHex method, of class SignatureTool.
     */
    @Test
    public void testBytesToHex() {
        System.out.println("bytesToHex");
        byte[] bytes = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        String expResult = "0102030405060708090A0B0C0D0E0F";
        String result = SignatureTool.bytesToHex(bytes);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of HexToBytes method, of class SignatureTool.
     */
    @Test
    public void testHexToBytes() {
        System.out.println("HexToBytes");
        String hexString = "1D74EA5C";
        byte[] expResult = {29, 116, -22, 92};
        byte[] result = SignatureTool.HexToBytes(hexString);
        for(int i = 0; i<result.length; i++){
            assertEquals(expResult[i], result[i]);
        }
    }

    /**
     * Test of sign method, of class SignatureTool.
     */
    @Test
    public void testSign() throws Exception {
        System.out.println("sign");
        String dataToSign = "test";
        SignatureTool instance = new SignatureTool("SHA1withRSA");
        instance.initKeys("/RGSDigestTools/ds_keystore.jks", "changeit", "digsig_pair", "digsig", "qwe");
        String expResult = "B7B1C80CE7EC08CA9419CE9B1DB72A8804C18F1BD575E5D60CB0168A46E2C32238DF5849347C13ABF73AFA081D9E8564E9158F795FF0EB9E5594535C5E568280978AF8447114E4E5191017E8053485E6A8F933DAB61E585A027217120C14FDE63DB5C0104AE7CCF89C5B543B59E654EBBA884CCADD58B2231DBD7811B41EAE4F1CBAB0ACA7AE22F95929E7AD0569E9429BF11B0D45B96530D96EAE259FA305A311C78025CAD04F906C9CD1823C72CC14B4E46ADF4DB67DBE2A38B63A5926FD379052318AD1580846060B468E54D8767A15A9CBDE24627A7AEA52148A47DA794643223338B2651A054057E9CB5BDAA89E941BB592D41CB62BCB44C20458F993B5";
        String result = instance.sign(dataToSign);
        assertEquals(expResult, result);
    }

    /**
     * Test of verify method, of class SignatureTool.
     */
    @Test
    public void testVerifyTrue() throws Exception {
        System.out.println("Verify");
        String dataToVerify = "test";
        byte[] signature = SignatureTool.HexToBytes("B7B1C80CE7EC08CA9419CE9B1DB72A8804C18F1BD575E5D60CB0168A46E2C32238DF5849347C13ABF73AFA081D9E8564E9158F795FF0EB9E5594535C5E568280978AF8447114E4E5191017E8053485E6A8F933DAB61E585A027217120C14FDE63DB5C0104AE7CCF89C5B543B59E654EBBA884CCADD58B2231DBD7811B41EAE4F1CBAB0ACA7AE22F95929E7AD0569E9429BF11B0D45B96530D96EAE259FA305A311C78025CAD04F906C9CD1823C72CC14B4E46ADF4DB67DBE2A38B63A5926FD379052318AD1580846060B468E54D8767A15A9CBDE24627A7AEA52148A47DA794643223338B2651A054057E9CB5BDAA89E941BB592D41CB62BCB44C20458F993B5");
        SignatureTool instance = new SignatureTool("SHA1withRSA");
        instance.initKeys("/RGSDigestTools/ds_keystore.jks", "changeit", "digsig_pair", "digsig", "qwe");
        boolean expResult = true;
        boolean result = instance.verify(dataToVerify, signature);
        assertEquals(expResult, result);

    }

        @Test
    public void testVerifyFalse() throws Exception {
        System.out.println("verify");
        String dataToVerify = "test";
        byte[] signature = SignatureTool.HexToBytes("B7B1C80CE7EC08CA9419CE9B1DB72A8804C18F1BD575E5D60CB0168A46E2C32238DF5849347C13ABF73AFA081D9E8564E9158F795FF0EB9E5594535C5E568280978AF8447114E4E5191017E8053485E6A8F933DAB61E585A027217120C14FDE63DB5C0104AE7CCF89C5B543B59E654EBBA884CCADD58B2231DBD7811B41EAE4F1CBAB0ACA7AE22F95929E7AD0569E9429BF11B0D45B96530D96EAE259FA305A311C78025CEC04F906C9CD1823C72CC14B4E46ADF4DB67DBE2A38B63A5926FD379052318AD1580846060B468E54D8767A15A9CBDE24627A7AEA52148A47DA794643223338B2651A054057E9CB5BDAA89E941BB592D41CB62BCB44C20458F993B5");
        SignatureTool instance = new SignatureTool("SHA1withRSA");
        instance.initKeys("/RGSDigestTools/ds_keystore.jks", "changeit", "digsig_pair", "digsig", "qwe");
        boolean expResult = false;
        boolean result = instance.verify(dataToVerify, signature);
        assertEquals(expResult, result);

    }
    
    /**
     * Test of initKeys method, of class SignatureTool.
     */
    @Test
    public void testInitKeys() throws Exception {
        System.out.println("initKeys");
        String pKeyStorePath = "/RGSDigestTools/ds_keystore.jks";
        String pKeyStorePasswd = "changeit";
        String pDSAlias = "digsig_pair";
        String pPrivKeyPasswd = "digsig";
        String pCheckDSAlias = "qwe";
        SignatureTool instance = new SignatureTool("SHA1withRSA");;
        instance.initKeys(pKeyStorePath, pKeyStorePasswd, pDSAlias, pPrivKeyPasswd, pCheckDSAlias);
    }

    /**
     * Test of showKeys method, of class SignatureTool.
     */
    //@Test
    public void testShowKeys() throws Exception {
        System.out.println("showKeys");
        SignatureTool instance = new SignatureTool("SHA1withRSA");
        instance.initKeys("/RGSDigestTools/ds_keystore.jks", "changeit", "digsig_pair", "digsig", "qwe");
        String expResult = "";
        String result = instance.showKeys();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
    
     @Test
    public void IntegrityTest() throws Exception{
        try {
            System.out.println("IntegrityTest:");
            SignatureTool st = new SignatureTool("SHA1withRSA");
            st.initKeys("/RGSDigestTools/ds_keystore.jks", "changeit", "digsig_pair", "digsig", "qwe");
            String signature = st.sign("test");
            System.out.println("    " + "Signature of \"test\": " + signature);
            byte[] b_arr = SignatureTool.HexToBytes(signature);
            System.out.println("    " + "Sing verification: " + st.verify("test", b_arr));
            assertEquals(st.verify("test", b_arr), true);
            
        } catch (UnrecoverableEntryException ex) {
            fail(ex.getMessage());
        }
    }
    
}

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
        String dataToSign = "mti=5300&agent_id=1&pay_dt=20100713101012&terminal=65014&service_code=7103&pay_method=71000&account=79020000001";
        SignatureTool instance = new SignatureTool("SHA1withRSA");
        //instance.initKeysWithKeystore("/RGSDigestTools/ds_keystore.jks", "changeit", "digsig_pair", "digsig", "qwe");
        instance.initKeysWithFiles("/RGSDigestTools/ds_sign_key.der", "/RGSDigestTools/ds_check_pubkey.der");
        String expResult = "5e3e020ce180ff35f25b4e383c46f56ca63c8bad187e4105be5ed49c979b849ccba16775780400a66559e3a0242386407168936553482373ce32019166e2eae4437c0c05c8d688c7060a1b25ece420cfc03cd44c1af78240bf3edba70d83b3236a8cbec888006362c3651679374a89079c41537b014e67c8186afd3a62d81ebecbe987f72cc4a36ab3e7302050d041fd5479b0ef8b01cb6fb0bae7392c5a8302538f897f86c07207f1769cccaa1d082683b5872262ff74bd9adaa56e1eef1d8504c76b902a82bbacf4116c7852d6d7885c2520a855ed1e150646fe765adc08dff0ca6b8100d19d769b4ff818caf3b47f7e8c1da22bb16bb402a325717922af63".toUpperCase();
        String result = instance.sign(dataToSign);
        assertEquals(expResult, result);
    }

    /**
     * Test of verify method, of class SignatureTool.
     */
    @Test
    public void testVerifyTrue() throws Exception {
        System.out.println("Verify");
        String dataToVerify = "5310&3&Неправильная цифровая подпись -758";
        byte[] signature = SignatureTool.HexToBytes("b19816e410ed31fb0b6c04d31f7173e6d5e2a0c6b34e53e62c751ba7e008215e950464cd9b2eeca743fe2458558b838f3e9417537011efa0db135e07de1c7ae3b31c846d666c1543e26a52a8dd9218e05e6c7ef1cc1727095021d7f009739cbf2ed89a00e768d6e15b3c4ab790d3a01fac8c731a0224bf685406fa5624057ca4a9134ff613bce07f8d6b35612f03b11c00d8408334980fcd2ee7349b5ef82375b49e72c2437a2a64853e04b2f9210cf2bfaeadb4636ea6bcc6ae4f6365b786de40692dbbbd922fda600b5c459ec518f0241aed6d67e5ff7ff0f5995c42dbde0cdc05296ba694a35a173cb16ee58a05f43c0f441d5d293ada9d0954d1b33af361");
        SignatureTool instance = new SignatureTool("SHA1withRSA");
        instance.initKeysWithFiles("/RGSDigestTools/ds_sign_key.der", "/RGSDigestTools/ds_check_pubkey.der");
        //instance.initKeysWithKeystore("/RGSDigestTools/ds_keystore.jks", "changeit", "digsig_pair", "digsig", "qwe");
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
        instance.initKeysWithKeystore("/RGSDigestTools/ds_keystore.jks", "changeit", "digsig_pair", "digsig", "qwe");
        boolean expResult = false;
        boolean result = instance.verify(dataToVerify, signature);
        assertEquals(expResult, result);

    }
    
    /**
     * Test of initKeysWithKeystore method, of class SignatureTool.
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
        instance.initKeysWithKeystore(pKeyStorePath, pKeyStorePasswd, pDSAlias, pPrivKeyPasswd, pCheckDSAlias);
    }

    /**
     * Test of showKeys method, of class SignatureTool.
     */
    //@Test
    public void testShowKeys() throws Exception {
        System.out.println("showKeys");
        SignatureTool instance = new SignatureTool("SHA1withRSA");
        instance.initKeysWithKeystore("/RGSDigestTools/ds_keystore.jks", "changeit", "digsig_pair", "digsig", "qwe");
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
            st.initKeysWithKeystore("/RGSDigestTools/ds_keystore.jks", "changeit", "digsig_pair", "digsig", "qwe");
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

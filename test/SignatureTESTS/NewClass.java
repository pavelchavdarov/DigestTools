/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package SignatureTESTS;

import RGSDigestTools.SignatureTool;
import java.security.UnrecoverableEntryException;
import java.util.logging.Level;
import java.util.logging.Logger;


import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author p.chavdarov
 */
public class NewClass {
    @Test
    public void main() throws Exception{
        try {
            SignatureTool st = new SignatureTool("SHA1withRSA");
            //st.initKeysWithKeystore("/RGSDigestTools/ds_keystore.jks", "changeit", "digsig_pair", "digsig", "qwe");
            st.initKeysWithFiles("/RGSDigestTools/ds_sign_key.der", "/RGSDigestTools/ds_check_pubkey.der");
            System.out.println(st.showKeys());
            String signature = st.sign("5310&3&Неправильная цифровая подпись -758");
            System.out.println("Signature of \"5310&3&Неправильная цифровая подпись -758\": " + signature);
            //System.out.println("Row signature of \"test\": " + new String(signatureRow));
            byte[] b_arr = SignatureTool.HexToBytes(signature);
            System.out.println("Sing verification: " + st.verify("test", b_arr));
            assertEquals(true, st.verify("5310&3&Неправильная цифровая подпись -758", b_arr));
            
        } catch (UnrecoverableEntryException ex) {
            Logger.getLogger(NewClass.class.getName()).log(Level.SEVERE, null, ex);
            fail(ex.getMessage());
        }
    }
}

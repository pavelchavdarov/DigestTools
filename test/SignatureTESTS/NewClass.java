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
            st.initKeys("/RGSDigestTools/ds_keystore.jks", "changeit", "digsig_pair", "digsig", "qwe");
            System.out.println(st.showKeys());
            String signature = st.sign("test");
            System.out.println("Signature of \"test\": " + signature);
            //System.out.println("Row signature of \"test\": " + new String(signatureRow));
            byte[] b_arr = SignatureTool.HexToBytes(signature);
            System.out.println("Sing verification: " + st.verify("test", b_arr));
            assertEquals(st.verify("test", b_arr), true);
            
        } catch (UnrecoverableEntryException ex) {
            Logger.getLogger(NewClass.class.getName()).log(Level.SEVERE, null, ex);
            fail(ex.getMessage());
        }
    }
}

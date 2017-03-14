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

/**
 *
 * @author p.chavdarov
 */
public class NewClass {
    public static void main(String[] args) throws Exception{
        try {
            SignatureTool st = new SignatureTool("SHA1withRSA");
            st.initKeys("/RGSDigestTools/ds_keystore.jks", "changeit", "digsig_pair", "digsig", "qwe");
            System.out.println(st.showKeys());
            String signature = st.sign("test");
            System.out.println("Signature of \"test\": " + signature);
            //System.out.println("Row signature of \"test\": " + new String(signatureRow));
            byte[] b_arr = SignatureTool.HexToBytes(signature);
//            char[] arr = signature.toCharArray();
//            System.out.println();
//            byte[] b_arr = new byte[arr.length/2];
//            byte b = 0;
//            int j = 0;
//            for(int i = 0; i+2<=arr.length;i+=2 ){
////                System.out.print(String.format("%s %s : ", arr[i], arr[i+1]));
//                b = (byte) Integer.parseInt(String.format("%s%s",arr[i],arr[i+1]), 16);
//                b_arr[j++] = (byte) (b);// | b2 ;
//                //System.out.println("b_arr["+ (j-1) + "]= " + (int)b_arr[j-1]);
//                
//            }
            //System.out.println("");
            //System.out.println("b_arr size: " + b_arr.length);
            //System.out.println("signature size: " + signature.length());
            System.out.println("Sing verification: " + st.verify("test", b_arr));
                   
//            System.out.println("Signature of \"test\": " + st.verify("test", "B7B1C80CE7EC08CA9419CE9B1DB72A8804C18F1BD575E5D60CB0168A46E2C32238DF5849347C13ABF73AFA081D9E8564E9158F795FF0EB9E5594535C5E568280978AF8447114E4E5191017E8053485E6A8F933DAB61E585A027217120C14FDE63DB5C0104AE7CCF89C5B543B59E654EBBA884CCADD58B2231DBD7811B41EAE4F1CBAB0ACA7AE22F95929E7AD0569E9429BF11B0D45B96530D96EAE259FA305A311C78025CAD04F906C9CD1823C72CC14B4E46ADF4DB67DBE2A38B63A5926FD379052318AD1580846060B468E54D8767A15A9CBDE24627A7AEA52148A47DA794643223338B2651A054057E9CB5BDAA89E941BB592D41CB62BCB44C20458F993B5"));

            
        } catch (UnrecoverableEntryException ex) {
            Logger.getLogger(NewClass.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}

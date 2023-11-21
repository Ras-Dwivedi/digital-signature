package gr.hcg.controllers;

import gr.hcg.services.UploadDocumentService;
import gr.hcg.sign.CreateStringSignatureBase;
import gr.hcg.sign.Signer;
import gr.hcg.views.JsonView;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.cms.CMSSignedData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;

@Controller
public class SignController {

    @Value("${check.config}")
    private String checkConfig;

    @Value("${signer.apikey}")
    private String signerapikey;

    @Value("${signer.docsUrlPrefix}")
    private String docsUrlPrefix;

    @Autowired
    Signer signer;

    @Autowired
    UploadDocumentService uploadDocumentService;
    private static final Logger logger = LogManager.getLogger(Signer.class);

    @GetMapping("/sign")
    public ModelAndView home(Model model) {
        model.addAttribute("message", "Please upload a pdf file to sign");
        model.addAttribute("config", checkConfig);
        return new ModelAndView("sign", model.asMap());

    }

    private ResponseEntity<byte[]> respondHtmlOrJson(Optional<Boolean> json, Model model, HttpServletResponse response) {
        if (json.isPresent()) {
            // Assuming JsonView.Render() returns a byte[] representation of the JSON.
            byte[] jsonData = JsonView.Render(model, response);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            return new ResponseEntity<>(jsonData, headers, HttpStatus.OK);
        } else {
            // Convert the HTML response to bytes and return.
            // This part might need further adjustments based on how you handle HTML responses.
            byte[] htmlData = "HTML response here".getBytes(StandardCharsets.UTF_8); // Placeholder
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.TEXT_HTML);
            return new ResponseEntity<>(htmlData, headers, HttpStatus.OK);
        }
    }

    @PostMapping("/sign")
    public  ResponseEntity<byte[]> singleFileUpload(Model model,
                                   @RequestParam(value = "file") MultipartFile file,
                                   @RequestParam(value = "apikey") String apikey,
                                   @RequestParam(value = "password") Optional<String> password,
                                   HttpServletResponse response ) {

        Optional<Boolean> json = Optional.of(true);
        model.addAttribute("uuid", null);
        model.addAttribute("path", null);
        if (file.isEmpty()) {
            model.addAttribute("message", "Empty file");
            model.addAttribute("error", true);
            return respondHtmlOrJson(json, model, response);
        }

        if(!apikey.equals(signerapikey)) {
            model.addAttribute("message", "Wrong api key");
            model.addAttribute("error", true);
            return respondHtmlOrJson(json, model, response);
        }


        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            Calendar signDate;
            signDate=signer.sign(file.getInputStream(), bos);

            // Get the signed PDF bytes
            byte[] signedPdfBytes = bos.toByteArray();

            // Set headers for the response
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_PDF);
            headers.setContentDispositionFormData("attachment", "signed_document.pdf");
            headers.setCacheControl("must-revalidate, post-check=0, pre-check=0");

            // Return the signed PDF in the response
            return new ResponseEntity<>(signedPdfBytes, headers, HttpStatus.OK);

        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException | IllegalStateException e) {
            model.addAttribute("error", true);
            model.addAttribute("message", "Error: " + e.getMessage());
            e.printStackTrace();
            //return "sign";
            return respondHtmlOrJson(json, model, response);
        }

    }



    /**
     *
     * This function takes a string as an returns the signature on the string along with the signature details
     * params
     *  * string
     *  * api key: to be removed
     *  * dsc password
     */
    @PostMapping(value="/signString", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public  Map signString(@RequestBody Map<String, String> request)
            throws UnrecoverableKeyException,
                    CertificateException,
                    KeyStoreException,
                    NoSuchAlgorithmException,
                    IOException {
        String plainText = request.get("plainText");
        String password = request.get("password");
        CreateStringSignatureBase signatureBase = new CreateStringSignatureBase(password);
        try {
            CMSSignedData sign = signatureBase.sign(plainText);
            String signerInfo = signatureBase.getSignerName();
            String signData = signatureBase.cmsToBase64(sign);
            Map<String, Object> responseMap = new HashMap<>();
            responseMap.put("success", true);
            responseMap.put("sign", signData);
            responseMap.put("signerInfo", signerInfo);
            responseMap.put("timestamp", System.currentTimeMillis());
            return responseMap;
        } catch (Exception e){
            e.printStackTrace();
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("success", "false");
            errorResponse.put("error", e.getMessage());
            return errorResponse;
        }
    }

    @PostMapping(value = "/sign/verify", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Map<String, Object> verifySignature(@RequestBody Map<String, String> request) throws Exception {
        if(!request.containsKey("signature")){
            Map<String, Object> responseMap = new HashMap<>();
            responseMap.put("success", false);
            responseMap.put("error", "signature cannot be empty");
            return responseMap;
        }
        String signature = request.get("signature");
        CreateStringSignatureBase signatureBase = new CreateStringSignatureBase();
        try {
            boolean isVerified = signatureBase.verifyString(signature);

            Map<String, Object> responseMap = new HashMap<>();
            Map<String, Object> dataMap = new HashMap<>();
            responseMap.put("success", true);
            dataMap.put("verified", isVerified);
            responseMap.put("data", dataMap);
            return responseMap;
        } catch (Exception e){
            e.printStackTrace();
            Map<String, Object> responseMap = new HashMap<>();
            responseMap.put("success", false);
            responseMap.put("error", e.getMessage());
            return responseMap;
        }
    }
}

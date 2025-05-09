package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.logging.Logging;
import burp.utils.MyScanCheck;

public class DirSearch implements BurpExtension {
    private Logging logging;
    private MontoyaApi montoyaApi;


    @Override
    public void initialize(MontoyaApi api) {
        this.montoyaApi = api;
        this.logging = api.logging();
        api.extension().setName("DirSearch");
        logging.logToOutput("======= DirSearch2.6 =======");
        logging.logToOutput("author: atom");
        logging.logToOutput("[+] DirSearch loaded");
        api.scanner().registerScanCheck(new MyScanCheck(api));
    }

    public class MyExtensionUnloadHandler implements ExtensionUnloadingHandler {
        @Override
        public void extensionUnloaded() {
            System.out.println("DirSearch unloaded");
        }
    }
}
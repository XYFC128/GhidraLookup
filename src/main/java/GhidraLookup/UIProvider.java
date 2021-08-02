package GhidraLookup;

import java.awt.Dimension;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ArrayList;

import javax.swing.BoxLayout;
import javax.swing.DefaultListModel;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkListener;

import docking.ComponentProvider;
import ghidra.framework.plugintool.Plugin;
import GhidraLookup.Win32Data.Constant;

class UIProvider extends ComponentProvider {

	private JPanel panel = new JPanel();
	private JTextField findTextField;
	private JEditorPane result;
	private Win32Data database;
	private DefaultListModel<String> listmodel = new DefaultListModel<String>();
	private JList<String> candidateResults = new JList<String>(listmodel);

	public UIProvider(Plugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
		database = new Win32Data();
		result = new JEditorPane();
		result.setEditorKit(JEditorPane.createEditorKitForContentType("text/html"));
		result.setEditable(false);
		buildPanel();
	}
	
	private void openLink(String url) {
	    String os = System.getProperty("os.name").toLowerCase();
	    Runtime rt = Runtime.getRuntime();
	    
	    try{

	        if (os.indexOf( "win" ) >= 0) {

	            // this doesn't support showing urls in the form of "page.html#nameLink" 
	            rt.exec( "rundll32 url.dll,FileProtocolHandler " + url);

	        } else if (os.indexOf( "mac" ) >= 0) {

	            rt.exec( "open " + url);

	            } else if (os.indexOf( "nix") >=0 || os.indexOf( "nux") >=0) {

	            // Do a best guess on unix until we get a platform independent way
	            // Build a list of browsers to try, in this order.
	            String[] browsers = {"epiphany", "firefox", "mozilla", "konqueror",
	           			             "netscape","opera","links","lynx"};
	            	
	            // Build a command string which looks like "browser1 "url" || browser2 "url" ||..."
	            StringBuffer cmd = new StringBuffer();
	            for (int i=0; i<browsers.length; i++)
	                cmd.append( (i==0  ? "" : " || " ) + browsers[i] +" \"" + url + "\" ");
	            	
	            rt.exec(new String[] { "sh", "-c", cmd.toString() });

	           } else {
	                return;
	           }
	       }catch (Exception e){
	        return;
	       }
	      return;	
	}

	private void buildPanel() {
		findTextField = new JTextField(30);
		findTextField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				showAutocompleteResult();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				showAutocompleteResult();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				showAutocompleteResult();
			}
			
			public void showAutocompleteResult() {
				if (findTextField.getText()==null) return;
				listmodel.clear();
				listmodel.addAll(database.getFunctionList(findTextField.getText()));
				candidateResults.setModel(listmodel);
			}
			
		});
		
		MouseListener mouseListener = new MouseAdapter() {
		    public void mouseClicked(MouseEvent e) {
		        if (e.getClickCount() == 1) {
		           String selectedItem = candidateResults.getSelectedValue();
		          queryWin32Data(selectedItem);
		         }
		    }
		};
		candidateResults.addMouseListener(mouseListener);
		
		result.addHyperlinkListener(new HyperlinkListener() {
		    public void hyperlinkUpdate(HyperlinkEvent e) {
		        if(e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
		        	openLink(e.getURL().toString());
		        }
		    }
		});
		
		// layout
		
		
		findTextField.setMaximumSize(new Dimension(Short.MAX_VALUE, 15));
		JPanel leftPane = new JPanel();
		leftPane.setLayout(new BoxLayout(leftPane, BoxLayout.Y_AXIS));
		leftPane.setMaximumSize(new Dimension(250, Short.MAX_VALUE));
		leftPane.setPreferredSize(new Dimension(250, 500));
		leftPane.add(new JScrollPane(candidateResults));
		leftPane.add(findTextField);
		
		JScrollPane scrollPane2 = new JScrollPane(result);
		scrollPane2.setPreferredSize(new Dimension(500, 500));
		
		panel.add(leftPane);
        panel.add(scrollPane2);
	}
	
	public void openWindowByClicking(String token) {
		if(token == null || token.isBlank())
			return;
		findTextField.setText(token);
		queryWin32Data(token);
	}
	
	private void queryWin32Data(String functionName) {
		if (!database.contains(functionName)) {
			result.setText(functionName + " is not a Win32 function");
			return;
		}
		String showData = "<font size = \"6\"><a href=\""+ database.getURL(functionName) +"\">MSDN Link</a></font><br>";
		showData += "<font size = \"6\"><font color=\"blue\">" + database.getReturnType(functionName) + "</font>" ;
		showData += " <font color=\"green\">" + functionName + "</font>(";
		int parameterCount = database.getNumParameter(functionName);
		for (int i=0;i<parameterCount;i++) {
			showData += "  " + database.getParameterType(functionName, i) 
			+ "  " + database.getNthParameterName(functionName, i);
			if (i+1 != parameterCount) showData += ",";
		}
		showData += ")</font><br>";
		
		showData += database.getDescription(functionName) 
				+ "<br><br><font size=\"5\"><strong>Parameters:</strong></font><br>";
		for (int i=0;i<parameterCount;i++) {
			showData += "<b>" + database.getParameterType(functionName, i) 
			+ "  " + database.getNthParameterName(functionName, i)
			+ "</b>: "
			+ database.getParameterDescription(functionName
					, database.getNthParameterName(functionName, i));
			
			ArrayList<Constant> replacements = database.getParameterReplacements
					(functionName,database.getNthParameterName(functionName, i));
			int replacementCount = replacements.size();
			if (replacementCount > 0) {
				showData += "<br><u>Possible Parameter Replacements: </u>";
				
				for (int j=0;j<replacementCount;j++) {
					showData += "<br>";
					showData += replacements.get(j).name+ " = " + replacements.get(j).value;
					if (j+1 != replacementCount) showData += ",";
				}
			}
			
			showData += "<br><br>";
		}
		
		
		result.setText(showData);
	}
	
	public Win32Data getDatabase() {
		return database;
	}


	@Override
	public JComponent getComponent() {
		return panel;
	}

}
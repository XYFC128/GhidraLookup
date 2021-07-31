package ghidra_win32;

import java.awt.BorderLayout;
import java.awt.Desktop;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.IOException;
import java.net.URISyntaxException;

import javax.swing.BoxLayout;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkListener;

import docking.ComponentProvider;
import ghidra.framework.plugintool.Plugin;

class UIProvider extends ComponentProvider {

	private JPanel panel = new JPanel();
	private JTextField findTextField;
	private JEditorPane result;
	private Win32Data database;
	private DefaultListModel<String> listmodel = new DefaultListModel<String>();
	private JList<String> candidateResults = new JList<String>(listmodel);

	public UIProvider(Plugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		panel.setLayout(new BoxLayout(panel,BoxLayout.Y_AXIS));
		database = new Win32Data();
		result = new JEditorPane();
		result.setEditorKit(JEditorPane.createEditorKitForContentType("text/html"));
		result.setEditable(false);
		buildPanel();
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
		JPanel search = new JPanel();
		search.add(findTextField);
		
		MouseListener mouseListener = new MouseAdapter() {
		    public void mouseClicked(MouseEvent e) {
		        if (e.getClickCount() == 2) {
		           String selectedItem = candidateResults.getSelectedValue();
		          queryWin32Data(selectedItem);
		         }
		    }
		};
		candidateResults.addMouseListener(mouseListener);
		JScrollPane scrollPane1 = new JScrollPane(candidateResults);
		result.addHyperlinkListener(new HyperlinkListener() {
		    public void hyperlinkUpdate(HyperlinkEvent e) {
		        if(e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
		        	Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
		        	if (desktop==null)  return;
		        	if(desktop.isDesktopSupported()) {
		        		try {
							desktop.getDesktop().browse(e.getURL().toURI());
						} catch (IOException | URISyntaxException e1) {
							e1.printStackTrace();
						}
			        }
		        }
		    }
		});
		JScrollPane scrollPane2 = new JScrollPane(result);
		
		JPanel endPanel = new JPanel(new GridLayout(1,0));
        endPanel.add(scrollPane1);
        endPanel.add(scrollPane2);
		panel.add(search);
		panel.add(endPanel);
	}
	
	public void openWindowByClicking(String token) {
		findTextField.setText(token);
		queryWin32Data(token);
	}
	
	private void queryWin32Data(String functionName) {
		if (!database.contains(functionName)) {
			result.setText(functionName + " is not a Win32 function");
			return;
		}
		result.setText("<a href=\""+ database.getURL(functionName) +"\">" + functionName +"</a>");
		//result.
	}


	@Override
	public JComponent getComponent() {
		return panel;
	}

}
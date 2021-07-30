package ghidra_win32;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

import javax.swing.BoxLayout;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.ComponentProvider;
import ghidra.framework.plugintool.Plugin;

class UIProvider extends ComponentProvider {

	private JPanel panel = new JPanel();
	private JTextField findTextField;
	private JTextArea result;
	private Win32Data database;
	private DefaultListModel<String> listmodel = new DefaultListModel<String>();
	private JList<String> candidateResults = new JList<String>(listmodel);

	public UIProvider(Plugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		panel.setLayout(new BoxLayout(panel,BoxLayout.Y_AXIS));
		database = new Win32Data();
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
		JScrollPane scrollPane = new JScrollPane(candidateResults);
		
		result = new JTextArea(10,40);
		
		JPanel endPanel = new JPanel(new GridLayout(1,0));
        endPanel.add(scrollPane);
        endPanel.add(result);
		panel.add(search);
		panel.add(endPanel);
	}
	
	public void openWindowByClicking(String token) {
		findTextField.setText(token);
		queryWin32Data(token);
	}
	
	private void queryWin32Data(String token) {
		result.setText(token);
	}


	@Override
	public JComponent getComponent() {
		return panel;
	}

}
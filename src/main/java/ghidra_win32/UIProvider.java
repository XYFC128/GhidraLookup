package ghidra_win32;

import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

import javax.swing.BoxLayout;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JList;
import javax.swing.JMenu;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.ComponentProvider;
import docking.action.DockingAction;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

class UIProvider extends ComponentProvider {

	private JPanel panel = new JPanel();
	private JButton button;
	private JTextField findTextField;
	private JTextArea result;
	private Win32Data database;
	private DefaultListModel<String> listmodel = new DefaultListModel<String>();
	private JList<String> candidateResults = new JList<String>(listmodel);

	public UIProvider(Plugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		panel.setLayout(new BoxLayout(panel, BoxLayout.PAGE_AXIS));
		database = new Win32Data();
		buildPanel();
	}

	private void buildPanel() {
		JPanel searchPanel = new JPanel();
		searchPanel.setLayout(new BoxLayout(searchPanel, BoxLayout.LINE_AXIS));
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
		searchPanel.add(findTextField);	
		button = new JButton("Search");
		button.addActionListener(new java.awt.event.ActionListener(){
			@Override
			public void actionPerformed(ActionEvent e) {
				candidateResults.setVisible(false);
				queryWin32Data(findTextField.getText());
			}
		 });
		searchPanel.add(button);
		
		JPanel resultPanel = new JPanel();
		resultPanel.setLayout(new BoxLayout(resultPanel, BoxLayout.LINE_AXIS));
		result = new JTextArea(10,40);
		resultPanel.add(result);
		
		panel.add(searchPanel);
		panel.add(candidateResults);
		MouseListener mouseListener = new MouseAdapter() {
		    public void mouseClicked(MouseEvent e) {
		        if (e.getClickCount() == 2) {
		        	System.out.println(candidateResults.getSelectedIndex());
		           String selectedItem = candidateResults.getSelectedValue();
		           findTextField.setText(selectedItem);
		         }
		    }
		};
		candidateResults.addMouseListener(mouseListener);
		panel.add(resultPanel);
	}
	
	public void openWindowByClicking(String token) {
		findTextField.setText(token);
		queryWin32Data(token);
	}
	
	private void queryWin32Data(String token) {
		//System.out.println(token + " " + database.contains(token));
	}


	@Override
	public JComponent getComponent() {
		return panel;
	}

}

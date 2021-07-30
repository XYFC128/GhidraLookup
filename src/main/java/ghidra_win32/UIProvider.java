package ghidra_win32;

import java.awt.event.ActionEvent;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
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
				System.out.println("afa");
				showAutocompleteResult();
			}

			@Override
			public void removeUpdate(DocumentEvent e) { }

			@Override
			public void changedUpdate(DocumentEvent e) { }
			
			public void showAutocompleteResult() {
				//TODO: show autocomplete result
				JTextField textField = new JTextField();
				JPopupMenu popup = new JPopupMenu();
				textField.add(popup);
				textField.setComponentPopupMenu(popup);

				// 2. Let's create a sub-menu that "expands"
				JMenu subMenu = new JMenu("m");
				subMenu.add("m1");
				subMenu.add("m2");

				// 3. Finally, add the sub-menu and item to the popup
				popup.add(subMenu);
				popup.add("n");
			}
			
		});
		searchPanel.add(findTextField);	
		button = new JButton("Search");
		button.addActionListener(new java.awt.event.ActionListener(){
			@Override
			public void actionPerformed(ActionEvent e) {
				queryWin32Data(findTextField.getText());
			}
		 });
		searchPanel.add(button);
		
		JPanel resultPanel = new JPanel();
		resultPanel.setLayout(new BoxLayout(resultPanel, BoxLayout.LINE_AXIS));
		result = new JTextArea(10,40);
		resultPanel.add(result);
		
		panel.add(searchPanel);
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

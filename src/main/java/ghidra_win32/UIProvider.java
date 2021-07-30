package ghidra_win32;

import java.awt.event.ActionEvent;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import docking.ComponentProvider;
import docking.action.DockingAction;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

// TODO: If provider is desired, it is recommended to move it to its own file
class UIProvider extends ComponentProvider {

	private JPanel panel = new JPanel();
	private DockingAction action;
	private ProgramLocation currentLocation;
	private Program currentProgram;
	private JButton button;

	public UIProvider(Plugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		panel.setLayout(new BoxLayout(panel, BoxLayout.PAGE_AXIS));
		buildPanel();
		createActions();
	}

	// Customize GUI
	private void buildPanel() {
		JPanel searchPanel = new JPanel();
		searchPanel.setLayout(new BoxLayout(searchPanel, BoxLayout.LINE_AXIS));
		JTextField findTextField = new JTextField(30);
		searchPanel.add(findTextField);	
		button = new JButton("Search");
		button.addActionListener(new java.awt.event.ActionListener(){
			@Override
			public void actionPerformed(ActionEvent e) {
				
			}
		      
		 });
		searchPanel.add(button);
		
		JPanel resultPanel = new JPanel();
		resultPanel.setLayout(new BoxLayout(resultPanel, BoxLayout.LINE_AXIS));
		JTextArea result = new JTextArea(10,40);
		resultPanel.add(result);
		
		panel.add(searchPanel);
		panel.add(resultPanel);
		
		setVisible(true);
	}

	// TODO: Customize actions
	private void createActions() {
		
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
	
	private void locationChanged(Program program, ProgramLocation loc) {
		currentLocation = loc;
		currentProgram = program;
	}

}

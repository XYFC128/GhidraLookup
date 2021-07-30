/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra_win32;

import java.awt.event.ActionEvent;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.Tool;
import docking.action.DockingAction;
import docking.action.DockingActionIf;
import docking.action.MenuData;
import docking.actions.PopupActionProvider;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompilerLocation;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Plugin short description goes here.",
	description = "Plugin long description goes here."
)
//@formatter:on
public class ghidra_win32Plugin extends ProgramPlugin implements PopupActionProvider {

	MyProvider provider;
	// data
	String cur_function_name;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 * @throws IOException 
	 */
	public ghidra_win32Plugin(PluginTool tool) {
		super(tool, true, true);
		
		cur_function_name = new String();
		
		// TODO: Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new MyProvider(this, pluginName);

		// TODO: Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	@Override
	public void init() {
		super.init();
		tool.addPopupActionProvider(this);
		// TODO: Acquire services if necessary
	}
	
	@Override
	public List<DockingActionIf> getPopupActions(Tool tool, ActionContext ctx) {
		// TODO Auto-generated method stub
		if(currentLocation instanceof DecompilerLocation) {
			ClangToken token = ((DecompilerLocation)currentLocation).getToken();
			if(token instanceof ClangFuncNameToken)
			{
				List<DockingActionIf> list = new ArrayList<>();
				DockingAction act = new DockingAction("My Action", ctx.getComponentProvider().getName()) {
					@Override
					public void actionPerformed(ActionContext context) {
						//Msg.showInfo(getClass(), provider.getComponent(), "Custom Action", "hello");
						showWindow();
					}
				};
				act.setEnabled(true);
				act.setPopupMenuData(new MenuData(new String[] { "My Action" }, "Decompile"));
				act.markHelpUnnecessary();
				list.add(act);
				
				//cur_function_name = fn_token.getText();
				System.out.println(token.getText());
				return list;
			}
		}
		cur_function_name = "";
		return new ArrayList<>();
	}
	
	public void showWindow() {
		provider.setVisible(true);
	}

	// TODO: If provider is desired, it is recommended to move it to its own file
	private static class MyProvider extends ComponentProvider {

		private JPanel panel = new JPanel();
		private DockingAction action;
		private ProgramLocation currentLocation;
		private Program currentProgram;
		private JButton button;

		public MyProvider(Plugin plugin, String owner) {
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
}

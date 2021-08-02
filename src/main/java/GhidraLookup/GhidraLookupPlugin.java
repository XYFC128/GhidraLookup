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
package GhidraLookup;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import docking.ActionContext;
import docking.Tool;
import docking.action.DockingAction;
import docking.action.DockingActionIf;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.actions.PopupActionProvider;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompilerLocation;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import resources.Icons;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "GhidraLookupPlugin",
	category = PluginCategoryNames.COMMON,
	shortDescription = "Lookip Win API Documentation",
	description = "The plugin aims to provide support for Win32 API reversing in PE executables."
)
//@formatter:on
public class GhidraLookupPlugin extends ProgramPlugin implements PopupActionProvider {

	UIProvider provider;
	// data
	Win32Data m_database;
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 * @throws IOException 
	 */
	public GhidraLookupPlugin(PluginTool tool) {
		super(tool, true, true);
		
		// TODO: Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new UIProvider(this, pluginName);
		
		// TODO: Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
		
		m_database = provider.getDatabase();
	}

	@Override
	public void init() {
		super.init();
		tool.addPopupActionProvider(this);
		setupAction();
	}
	
	private void setupAction() {
		DockingAction act = new DockingAction("Lookup Win32 Documentation", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				showWindow(null);
			}
		};
		act.setEnabled(true);
		act.setToolBarData(new ToolBarData(Icons.HELP_ICON));
		act.markHelpUnnecessary();
		
		tool.addAction(act);
	}
	
	@Override
	public List<DockingActionIf> getPopupActions(Tool tool, ActionContext ctx) {
		// TODO Auto-generated method stub
		if(currentLocation instanceof DecompilerLocation) {
			ClangToken token = ((DecompilerLocation)currentLocation).getToken();
			if((token instanceof ClangFuncNameToken) && m_database.contains(token.getText()))
			{
				List<DockingActionIf> list = new ArrayList<>();
				DockingAction act = new DockingAction("Lookup Win32 Documentation", ctx.getComponentProvider().getName()) {
					@Override
					public void actionPerformed(ActionContext context) {
						showWindow(token.getText());
					}
				};
				act.setEnabled(true);
				act.setPopupMenuData(new MenuData(new String[] { "Lookup Win32 Documentation" }, "Ghidra Win32"));
				act.markHelpUnnecessary();
				list.add(act);
				

				return list;
			}
		}
		return new ArrayList<>();
	}
	
	@Override
	protected void locationChanged(ProgramLocation loc) {
		super.locationChanged(loc);
		if(loc instanceof DecompilerLocation) {
			ClangToken token = ((DecompilerLocation)currentLocation).getToken();
			if((token instanceof ClangFuncNameToken) && m_database.contains(token.getText())) 
				provider.openWindowByClicking(token.getText());
		}
	}
	
	public void showWindow(String token) {
		provider.openWindowByClicking(token);
		provider.setVisible(true);
	}

}

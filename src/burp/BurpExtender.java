package burp;

import javax.swing.*;
import java.net.URL;
import java.util.*;
import java.util.regex.*;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, IScannerCheck
{
	private IExtensionHelpers helpers;
	private IBurpExtenderCallbacks callbacks;
	private final static Pattern uuidPattern = Pattern.compile(
			"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
			Pattern.CASE_INSENSITIVE);
	private List<ToggleMenuItem> versionToggles;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	{
		callbacks.setExtensionName("UUID issues");
		callbacks.registerScannerCheck(this);
		callbacks.registerContextMenuFactory(this);
		this.callbacks = callbacks;
		this.helpers = callbacks.getHelpers();
		versionToggles = Arrays.asList(
				new ToggleMenuItem("UUID Version 1", callbacks, true),
				new ToggleMenuItem("UUID Version 2", callbacks, true),
				new ToggleMenuItem("UUID Version 3", callbacks),
				new ToggleMenuItem("UUID Version 4", callbacks),
				new ToggleMenuItem("UUID Version 5", callbacks),
				new ToggleMenuItem("Unrecognized Versions", callbacks)
		);
	}

	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseMsg) {
		List<IScanIssue> issues = new ArrayList<>();
		String request = helpers.bytesToString(baseMsg.getRequest());
		Matcher m = uuidPattern.matcher(request);
		URL url = null;
		while (m.find()) {
			if (url == null) {
				url = helpers.analyzeRequest(baseMsg.getHttpService(),
						baseMsg.getRequest()).getUrl();
			}
			UUID u;
			try {
				u = UUID.fromString(m.group());
			} catch (IllegalArgumentException iae) {
				// ignore invalid UUIDs
				continue;
			}
			IHttpRequestResponse msg = callbacks.applyMarkers(baseMsg,
					Collections.singletonList(new int[] { m.start(), m.end() }), null);

			if (isVersionEnabled(u.version())) {
				issues.add(new UuidIssue(msg, url, u));
			}
		}
		return issues;
	}

	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseMsg,
			IScannerInsertionPoint insertionPoint) {
		return null;
	}

	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		return existingIssue.getIssueDetail().equals(newIssue.getIssueDetail()) ? -1 : 0;
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		return (List<JMenuItem>) (List<? extends JMenuItem>) versionToggles;
	}

	private boolean isVersionEnabled(int version) {
		if (version < 1 || version >= versionToggles.size()) {
			version = versionToggles.size();
		}
		return versionToggles.get(version-1).isSelected();
	}
}

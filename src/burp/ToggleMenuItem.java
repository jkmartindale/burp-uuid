package burp;

import javax.swing.*;
import java.awt.event.MouseEvent;

/**
 * Modified {@code JCheckBoxMenuItem} that remembers its state across Burp sessions and doesn't close the menu when
 * clicked.
 */
public class ToggleMenuItem extends JCheckBoxMenuItem {
    /**
     * If there is no saved state for a {@code ToggleMenuItem} with the label {@code text}, the selection state will be
     * set to {@code defaultState}.
     *
     * @param text         the text of the checkbox menu item
     * @param defaultState default selected state of the checkbox menu item
     * @param callbacks    {@code IBurpExtenderCallbacks} object with preferences store
     */
    public ToggleMenuItem(String text, IBurpExtenderCallbacks callbacks, boolean defaultState) {
        super(text, defaultState);

        String savedState = callbacks.loadExtensionSetting(text);
        if (savedState != null) {
            setSelected(Boolean.parseBoolean(savedState));
        }

        this.addActionListener(e -> callbacks.saveExtensionSetting(text, String.valueOf(isSelected())));
    }

    /**
     * If there is no saved state for a {@code ToggleMenuItem} with the label {@code text}, the selection state will be
     * set to {@code false}.
     *
     * @param text      the text of the checkbox menu item
     * @param callbacks {@code IBurpExtenderCallbacks} object with preferences store
     */
    public ToggleMenuItem(String text, IBurpExtenderCallbacks callbacks) {
        this(text, callbacks, false);
    }

    /**
     * Prevents the menu from closing when clicking on this {@code JMenuItem}.
     *
     * @param e the mouse event
     */
    @Override
    protected void processMouseEvent(MouseEvent e) {
        // https://stackoverflow.com/a/34032642/3427178
        if (e.getID() == MouseEvent.MOUSE_RELEASED && contains(e.getPoint())) {
            doClick();
        } else {
            super.processMouseEvent(e);
        }
    }
}

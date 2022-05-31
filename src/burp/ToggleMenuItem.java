package burp;

import javax.swing.*;
import java.awt.event.MouseEvent;

public class ToggleMenuItem extends JCheckBoxMenuItem {
    /**
     * Constructs a {@code JCheckBoxMenuItem} that doesn't close the menu when clicked.
     * @param text the text of the check box menu item
     * @param b the selected state of the check box menu item
     */
    public ToggleMenuItem(String text, boolean b) {
        super(text, b);
    }

    @Override
    protected void processMouseEvent(MouseEvent e) {
        // https://stackoverflow.com/a/34032642/3427178
        if (e.getID() == MouseEvent.MOUSE_RELEASED && contains(e.getPoint())) {
            doClick();
            setArmed(true);
        } else {
            super.processMouseEvent(e);
        }
    }
}

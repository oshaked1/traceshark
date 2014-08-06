/* capture_interfaces_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include "capture_interfaces_dialog.h"
#include "capture_filter_combo.h"
#include "ui_capture_interfaces_dialog.h"
#include "compiled_filter_output.h"
#include "manage_interfaces_dialog.h"

#include "wireshark_application.h"

#ifdef HAVE_LIBPCAP

#include <QTimer>

#include "ui/capture_ui_utils.h"
#include "ui/capture_globals.h"
#include "ui/iface_lists.h"

#include "ui/ui_util.h"
#include "ui/utf8_entities.h"
#include "ui/preference_utils.h"

#include <cstdio>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/addr_resolv.h>

#include "sparkline_delegate.h"

// To do:
// - Set a size hint for item delegates.
// - Make promiscuous a checkbox.
// - Allow sorting by the traffic column? We'd have to subclass QTreeWidgetItem
//   (see ConversationTreeWidget).

const int stat_update_interval_ = 1000; // ms

#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
#define SHOW_BUFFER_COLUMN 1
#endif

#if defined(HAVE_PCAP_CREATE)
#define SHOW_MONITOR_COLUMN 1
#endif

/*
 * Symbolic names for column indices.
 */
enum
{
    col_interface_ = 0,
    col_traffic_,
    col_link_,
    col_pmode_,
    col_snaplen_,
    col_buffer_,
    col_monitor_,
    col_filter_,
    col_num_columns_
};

class InterfaceTreeWidgetItem : public QTreeWidgetItem
{
public:
    InterfaceTreeWidgetItem(QTreeWidget *tree) : QTreeWidgetItem(tree)  {}
    bool operator< (const QTreeWidgetItem &other) const;
};

CaptureInterfacesDialog::CaptureInterfacesDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::CaptureInterfacesDialog)
{
    ui->setupUi(this);

    stat_timer_ = NULL;
    stat_cache_ = NULL;

    // XXX - Enable / disable as needed
    start_bt_ = ui->buttonBox->addButton(tr("Start"), QDialogButtonBox::YesRole);

    start_bt_->setEnabled((global_capture_opts.num_selected > 0)? true: false);
    connect(start_bt_, SIGNAL(clicked(bool)), this, SLOT(start_button_clicked()));

    ui->interfaceTree->sortByColumn(col_interface_, Qt::AscendingOrder);
    ui->interfaceTree->setItemDelegateForColumn(col_interface_, &interface_item_delegate_);
    ui->interfaceTree->setItemDelegateForColumn(col_traffic_, new SparkLineDelegate());
    ui->interfaceTree->setItemDelegateForColumn(col_link_, &interface_item_delegate_);
    ui->interfaceTree->setItemDelegateForColumn(col_pmode_, &interface_item_delegate_);
    ui->interfaceTree->setItemDelegateForColumn(col_snaplen_, &interface_item_delegate_);
#ifdef SHOW_BUFFER_COLUMN
    ui->interfaceTree->setItemDelegateForColumn(col_buffer_, &interface_item_delegate_);
#else
    ui->interfaceTree->setColumnHidden(col_buffer_, true);
#endif
#ifdef SHOW_MONITOR_COLUMN
    ui->interfaceTree->setItemDelegateForColumn(col_monitor_, &interface_item_delegate_);
#else
    ui->interfaceTree->setColumnHidden(col_monitor_, true);
#endif
    ui->interfaceTree->setItemDelegateForColumn(col_filter_, &interface_item_delegate_);

    connect(ui->interfaceTree,SIGNAL(itemClicked(QTreeWidgetItem*,int)),this,SLOT(interfaceClicked(QTreeWidgetItem*,int)));
    connect(ui->interfaceTree, SIGNAL(itemSelectionChanged()), this, SLOT(interfaceSelected()));
    connect(ui->allFilterComboBox, SIGNAL(captureFilterSyntaxChanged(bool)), this, SLOT(allFilterChanged()));
    connect(this, SIGNAL(interfacesChanged()), ui->allFilterComboBox, SIGNAL(interfacesChanged()));
    connect(this, SIGNAL(ifsChanged()), this, SLOT(refreshInterfaceList()));
    connect(wsApp, SIGNAL(localInterfaceListChanged()), this, SLOT(updateLocalInterfaces()));
}

void CaptureInterfacesDialog::allFilterChanged()
{
    foreach (QTreeWidgetItem *ti, ui->interfaceTree->selectedItems()) {
        QString str = ui->allFilterComboBox->currentText();
        ti->setText(col_filter_, str);
    }
    updateWidgets();
}

void CaptureInterfacesDialog::interfaceSelected()
{
    interface_t device;

    if (!ui->interfaceTree->selectedItems().size()) {
        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            device.selected = false;
            device.locked = true;
            global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
            g_array_insert_val(global_capture_opts.all_ifaces, i, device);
        }
        global_capture_opts.num_selected = 0;
        start_bt_->setEnabled(false);
        emit setSelectedInterfaces();
        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            device.locked = false;
            global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
            g_array_insert_val(global_capture_opts.all_ifaces, i, device);
        }
    }
    updateWidgets();
}

void CaptureInterfacesDialog::updateWidgets()
{
    SyntaxLineEdit *sle = qobject_cast<SyntaxLineEdit *>(ui->allFilterComboBox->lineEdit());
    if (!sle) {
        return;
    }

    bool can_capture = false;

    if (ui->interfaceTree->selectedItems().count() > 0 && sle->syntaxState() != SyntaxLineEdit::Invalid) {
        can_capture = true;
    }

    ui->compileBPF->setEnabled(can_capture);
    start_bt_->setEnabled(can_capture);
}

void CaptureInterfacesDialog::interfaceClicked(QTreeWidgetItem *item, int column)
{
    Q_UNUSED(item)
    Q_UNUSED(column)
    guint i;
    QString filter = ui->allFilterComboBox->currentText();

    global_capture_opts.num_selected = 0;
    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        device->selected = FALSE;
    }

    foreach (QTreeWidgetItem *ti, ui->interfaceTree->selectedItems())
    {
        QString interface_name = ti->text(col_interface_);

        for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if (interface_name.compare(device->display_name)) {
                continue;
            } else {
                device->selected = TRUE;
                global_capture_opts.num_selected++;
                break;
            }
        }

        start_bt_->setEnabled((global_capture_opts.num_selected > 0) ? true: false);

        if (filter.compare(QString(""))) {
            emit interfacesChanged();
        }
        emit setSelectedInterfaces();
    }
}

CaptureInterfacesDialog::~CaptureInterfacesDialog()
{
    delete ui;
}

void CaptureInterfacesDialog::SetTab(int index)
{
    ui->tabWidget->setCurrentIndex(index);
}

void CaptureInterfacesDialog::on_capturePromModeCheckBox_toggled(bool checked)
{
    interface_t device;
    prefs.capture_prom_mode = checked;
    for (int row = 0; row < ui->interfaceTree->topLevelItemCount(); row++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, deviceMap[row]);
//        QString device_name = ui->interfaceTree->topLevelItem(row)->text(col_interface_);
        device.pmode = checked;
        global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, deviceMap[row]);
        g_array_insert_val(global_capture_opts.all_ifaces, deviceMap[row], device);
        QTreeWidgetItem *ti = ui->interfaceTree->topLevelItem(row);
        ti->setText(col_pmode_, checked? tr("enabled"):tr("disabled"));
    }
}

void CaptureInterfacesDialog::on_gbStopCaptureAuto_toggled(bool checked)
{
    global_capture_opts.has_file_duration = checked;
}

void CaptureInterfacesDialog::on_gbNewFileAuto_toggled(bool checked)
{
    global_capture_opts.multi_files_on = checked;
}

void CaptureInterfacesDialog::on_cbUpdatePacketsRT_toggled(bool checked)
{
    global_capture_opts.real_time_mode = checked;
}

void CaptureInterfacesDialog::on_cbAutoScroll_toggled(bool checked)
{
    Q_UNUSED(checked)
    //global_capture_opts.has_file_duration = checked;
}

void CaptureInterfacesDialog::on_cbExtraCaptureInfo_toggled(bool checked)
{
    global_capture_opts.show_info = checked;
}

void CaptureInterfacesDialog::on_cbResolveMacAddresses_toggled(bool checked)
{
    gbl_resolv_flags.mac_name = checked;
}

void CaptureInterfacesDialog::on_cbResolveNetworkNames_toggled(bool checked)
{
    gbl_resolv_flags.network_name = checked;
}

void CaptureInterfacesDialog::on_cbResolveTransportNames_toggled(bool checked)
{
    gbl_resolv_flags.transport_name = checked;
}

void CaptureInterfacesDialog::start_button_clicked()
{
    qDebug("Starting capture");

    saveOptionsToPreferences();
    emit setFilterValid(true);

    accept();
}

// Not sure why we have to do this manually.
void CaptureInterfacesDialog::on_buttonBox_rejected()
{
    saveOptionsToPreferences();
    reject();
}

void CaptureInterfacesDialog::on_buttonBox_helpRequested()
{
    // Probably the wrong URL.
    wsApp->helpTopicAction(HELP_CAPTURE_INTERFACES_DIALOG);
}

void CaptureInterfacesDialog::updateInterfaces()
{
    if(prefs.capture_pcap_ng) {
        ui->rbPcapng->setChecked(true);
    } else {
        ui->rbPcap->setChecked(true);
    }
    ui->capturePromModeCheckBox->setChecked(prefs.capture_prom_mode);

    ui->gbStopCaptureAuto->setChecked(global_capture_opts.has_file_duration);
    ui->gbNewFileAuto->setChecked(global_capture_opts.multi_files_on);

    ui->cbUpdatePacketsRT->setChecked(global_capture_opts.real_time_mode);
    ui->cbAutoScroll->setChecked(true);
    ui->cbExtraCaptureInfo->setChecked(global_capture_opts.show_info);

    ui->cbResolveMacAddresses->setChecked(gbl_resolv_flags.mac_name);
    ui->cbResolveNetworkNames->setChecked(gbl_resolv_flags.network_name);
    ui->cbResolveTransportNames->setChecked(gbl_resolv_flags.transport_name);

    ui->interfaceTree->clear();

    GList        *list;
    link_row     *linkr = NULL;
#ifdef SHOW_BUFFER_COLUMN
    gint          buffer;
#endif
    gint          snaplen;
    gboolean      hassnap, pmode;

    if (global_capture_opts.all_ifaces->len > 0) {
        interface_t device;

        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            QList<int> *points;

            device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);

            /* Continue if capture device is hidden */
            if (device.hidden) {
                continue;
            }
            deviceMap[ui->interfaceTree->topLevelItemCount()] = i;

            // Traffic sparklines
            points = new QList<int>();
            InterfaceTreeWidgetItem *ti = new InterfaceTreeWidgetItem(ui->interfaceTree);
            ti->setFlags(ti->flags() | Qt::ItemIsEditable);
            ti->setData(col_traffic_, Qt::UserRole, qVariantFromValue(points));

            ti->setText(col_interface_, device.display_name);
            if (device.no_addresses > 0) {
                QString addr_str = tr("%1: %2").arg(device.no_addresses > 1 ? tr("Addresses") : tr("Address")).arg(device.addresses);
                QTreeWidgetItem *addr_ti = new QTreeWidgetItem(ti);

                addr_str.replace('\n', ", ");
                addr_ti->setText(0, addr_str);
                addr_ti->setFlags(addr_ti->flags() ^ Qt::ItemIsSelectable);
                addr_ti->setFirstColumnSpanned(true);
                ti->setToolTip(col_interface_, QString("<span>%1</span>").arg(addr_str));
            } else {
                ti->setToolTip(col_interface_, tr("no addresses"));
            }

            QString linkname = "unknown";
            if(capture_dev_user_linktype_find(device.name) != -1) {
              device.active_dlt = capture_dev_user_linktype_find(device.name);
            }
            for (list = device.links; list != NULL; list = g_list_next(list)) {
                linkr = (link_row*)(list->data);
                if (linkr->dlt == device.active_dlt) {
                    linkname = linkr->name;
                    break;
                }
            }

            pmode = capture_dev_user_pmode_find(device.name);
            if (pmode != -1) {
                device.pmode = pmode;
            }
            hassnap = capture_dev_user_hassnap_find(device.name);
            snaplen = capture_dev_user_snaplen_find(device.name);
            if(snaplen != -1 && hassnap != -1) {
                /* Default snap length set in preferences */
                device.snaplen = snaplen;
                device.has_snaplen = hassnap;
            } else {
                /* No preferences set yet, use default values */
                device.snaplen = WTAP_MAX_PACKET_SIZE;
                device.has_snaplen = FALSE;
            }

            QString snaplen_string = device.has_snaplen ? QString::number(device.snaplen) : tr("default");

#ifdef SHOW_BUFFER_COLUMN
            if (capture_dev_user_buffersize_find(device.name) != -1) {
                buffer = capture_dev_user_buffersize_find(device.name);
                device.buffer = buffer;
            } else {
                device.buffer = DEFAULT_CAPTURE_BUFFER_SIZE;
            }
#endif

            interface_item_delegate_.setTree(ui->interfaceTree);
            ui->interfaceTree->setColumnWidth(col_link_, 100);
            ti->setText(col_link_, linkname);

            ti->setText(col_pmode_, device.pmode ? tr("enabled") : tr("disabled"));

            ti->setText(col_snaplen_, snaplen_string);
#ifdef SHOW_BUFFER_COLUMN
            ti->setText(col_buffer_, QString::number(device.buffer));
#endif
#ifdef SHOW_MONITOR_COLUMN
            ti->setText(col_monitor_, QString(device.monitor_mode_supported? (device.monitor_mode_enabled ? tr("enabled") : tr("disabled")) : tr("n/a")));
#endif
            gchar* prefFilter = capture_dev_user_cfilter_find(device.name);
            if (prefFilter) {
                device.cfilter = g_strdup(prefFilter);
            }
            ti->setText(col_filter_, device.cfilter);

            if (prefs.capture_device && strstr(prefs.capture_device, device.name) != NULL) {
                device.selected = TRUE;
                global_capture_opts.num_selected++;
            }
            ti->setSelected(device.selected);
            global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
            g_array_insert_val(global_capture_opts.all_ifaces, i, device);
        }
    }

    for (int i = 0; i < ui->interfaceTree->topLevelItemCount(); i++) {
        ui->interfaceTree->resizeColumnToContents(i);
    }

    start_bt_->setEnabled((global_capture_opts.num_selected > 0)? true: false);

    if (!stat_timer_) {
        updateStatistics();
        stat_timer_ = new QTimer(this);
        connect(stat_timer_, SIGNAL(timeout()), this, SLOT(updateStatistics()));
        stat_timer_->start(stat_update_interval_);
    }
}

void CaptureInterfacesDialog::refreshInterfaceList()
{
    updateInterfaces();
    emit interfaceListChanged();
}

void CaptureInterfacesDialog::updateLocalInterfaces()
{
    updateInterfaces();
}

void CaptureInterfacesDialog::updateStatistics(void)
{
    interface_t device;

    for (int row = 0; row < ui->interfaceTree->topLevelItemCount(); row++) {

        for (guint if_idx = 0; if_idx < global_capture_opts.all_ifaces->len; if_idx++) {
            QTreeWidgetItem *ti = ui->interfaceTree->topLevelItem(row);
            if (!ti) {
                continue;
            }
            device = g_array_index(global_capture_opts.all_ifaces, interface_t, if_idx);
            QString device_name = ti->text(col_interface_);
            if (device_name.compare(device.display_name) || device.hidden || device.type == IF_PIPE) {
                continue;
            }
            QList<int> *points = points = ti->data(col_traffic_, Qt::UserRole).value<QList<int> *>();
            points->append(device.packet_diff);
            ti->setData(col_traffic_, Qt::UserRole, qVariantFromValue(points));
        }
    }
    ui->interfaceTree->viewport()->update();
}

void CaptureInterfacesDialog::on_compileBPF_clicked()
{
    QStringList interfaces;
    foreach (QTreeWidgetItem *ti, ui->interfaceTree->selectedItems()) {
        interfaces.append(ti->text(col_interface_));
    }

    QString filter = ui->allFilterComboBox->currentText();
    CompiledFilterOutput *cfo = new CompiledFilterOutput(this, interfaces, filter);

    cfo->show();
}

void CaptureInterfacesDialog::saveOptionsToPreferences()
{
    interface_t device;
    gchar *new_prefs, *tmp_prefs;

    for (int col = col_link_; col <= col_filter_; col++){
        if (ui->interfaceTree->isColumnHidden(col)) {
            continue;
        }
        /* All entries are separated by comma. There is also one before the first interface to be able to identify
           word boundaries. As 'lo' is part of 'nflog' an exact match is necessary. */
        switch (col) {
        case col_link_:
            new_prefs = (gchar *)g_malloc0(MAX_VAL_LEN);

            for (int row = 0; row < ui->interfaceTree->topLevelItemCount(); row++) {
                device = g_array_index(global_capture_opts.all_ifaces, interface_t, deviceMap[row]);
                if (device.active_dlt == -1) {
                    continue;
                }
                g_strlcat(new_prefs, ",", MAX_VAL_LEN);
                tmp_prefs = g_strdup_printf("%s(%d)", device.name, device.active_dlt);
                g_strlcat(new_prefs, tmp_prefs, MAX_VAL_LEN);
                g_free(tmp_prefs);
            }
            g_free(prefs.capture_devices_linktypes);
            prefs.capture_devices_linktypes = new_prefs;
            break;
#ifdef SHOW_BUFFER_COLUMN
        case col_buffer_:
            new_prefs = (gchar *)g_malloc0(MAX_VAL_LEN);

            for (int row = 0; row < ui->interfaceTree->topLevelItemCount(); row++) {
                device = g_array_index(global_capture_opts.all_ifaces, interface_t, deviceMap[row]);
                if (device.buffer == -1) {
                    continue;
                }
                g_strlcat(new_prefs, ",", MAX_VAL_LEN);
                tmp_prefs = g_strdup_printf("%s(%d)", device.name, device.buffer);
                g_strlcat(new_prefs, tmp_prefs, MAX_VAL_LEN);
                g_free(tmp_prefs);
            }
            g_free(prefs.capture_devices_buffersize);
            prefs.capture_devices_buffersize = new_prefs;
            break;
#endif // HAVE_BUFFER_SETTING
        case col_snaplen_:
            new_prefs = (gchar *)g_malloc0(MAX_VAL_LEN);

            for (int row = 0; row < ui->interfaceTree->topLevelItemCount(); row++) {
                device = g_array_index(global_capture_opts.all_ifaces, interface_t, deviceMap[row]);
                g_strlcat(new_prefs, ",", MAX_VAL_LEN);
                tmp_prefs = g_strdup_printf("%s:%d(%d)", device.name, device.has_snaplen, (device.has_snaplen?device.snaplen:WTAP_MAX_PACKET_SIZE));
                g_strlcat(new_prefs, tmp_prefs, MAX_VAL_LEN);
                g_free(tmp_prefs);
            }
            g_free(prefs.capture_devices_snaplen);
            prefs.capture_devices_snaplen = new_prefs;
            break;
        case col_pmode_:
            new_prefs = (gchar *)g_malloc0(MAX_VAL_LEN);

            for (int row = 0; row < ui->interfaceTree->topLevelItemCount(); row++) {
                device = g_array_index(global_capture_opts.all_ifaces, interface_t, deviceMap[row]);
                if (device.pmode == -1) {
                    continue;
                }
                g_strlcat(new_prefs, ",", MAX_VAL_LEN);
                tmp_prefs = g_strdup_printf("%s(%d)", device.name, device.pmode);
                g_strlcat(new_prefs, tmp_prefs, MAX_VAL_LEN);
                g_free(tmp_prefs);
            }
            g_free(prefs.capture_devices_pmode);
            prefs.capture_devices_pmode = new_prefs;
            break;
#ifdef SHOW_MONITOR_COLUMN
        case col_monitor_:
            new_prefs = (gchar *)g_malloc0(MAX_VAL_LEN);

            for (int row = 0; row < ui->interfaceTree->topLevelItemCount(); row++) {
                device = g_array_index(global_capture_opts.all_ifaces, interface_t, deviceMap[row]);
                if (!device.monitor_mode_supported || (device.monitor_mode_supported && !device.monitor_mode_enabled)) {
                    continue;
                }
                g_strlcat(new_prefs, ",", MAX_VAL_LEN);
                tmp_prefs = g_strdup_printf("%s", device.name);
                g_strlcat(new_prefs, tmp_prefs, MAX_VAL_LEN);
                g_free(tmp_prefs);
            }
            g_free(prefs.capture_devices_monitor_mode);
            prefs.capture_devices_monitor_mode = new_prefs;
            break;
#endif // HAVE_MONITOR_SETTING
        case col_filter_:
            new_prefs = (gchar *)g_malloc0(MAX_VAL_LEN);

            for (int row = 0; row < ui->interfaceTree->topLevelItemCount(); row++) {
                device = g_array_index(global_capture_opts.all_ifaces, interface_t, deviceMap[row]);
                if (!device.cfilter) {
                    continue;
                }
                g_strlcat(new_prefs, ",", MAX_VAL_LEN);
                tmp_prefs = g_strdup_printf("%s(%s)", device.name, device.cfilter);
                g_strlcat(new_prefs, tmp_prefs, MAX_VAL_LEN);
                g_free(tmp_prefs);
            }
            g_free(prefs.capture_devices_filter);
            prefs.capture_devices_filter = new_prefs;
            break;
        }
    }
    if (!prefs.gui_use_pref_save) {
        prefs_main_write();
    }
}


void CaptureInterfacesDialog::on_manage_clicked()
{
    saveOptionsToPreferences();
    ManageInterfacesDialog *dlg = new ManageInterfacesDialog(this);
    dlg->show();
}

//
// InterfaceTreeItem
//
bool InterfaceTreeWidgetItem::operator< (const QTreeWidgetItem &other) const {
    if (treeWidget()->sortColumn() == col_traffic_) {
        QList<int> *points = data(col_traffic_, Qt::UserRole).value<QList<int> *>();
        QList<int> *other_points = other.data(col_traffic_, Qt::UserRole).value<QList<int> *>();
        double avg = 0, other_avg = 0;
        foreach (int point, *points) {
            avg += (double) point / points->length();
        }
        foreach (int point, *other_points) {
            other_avg += (double) point / other_points->length();
        }
        return avg < other_avg;
    }
    return QTreeWidgetItem::operator<(other);
}


//
// InterfaceTreeDelegate
//

#include <QComboBox>

InterfaceTreeDelegate::InterfaceTreeDelegate(QObject *parent)
    : QStyledItemDelegate(parent)
{
}


InterfaceTreeDelegate::~InterfaceTreeDelegate()
{
}


QWidget* InterfaceTreeDelegate::createEditor( QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index ) const
{
    Q_UNUSED(option);
    QWidget *w = NULL;
#ifdef SHOW_BUFFER_COLUMN
    gint buffer = DEFAULT_CAPTURE_BUFFER_SIZE;
#endif
    guint snap = WTAP_MAX_PACKET_SIZE;
    GList *links = NULL;

    if (index.column() > 1) {
        interface_t device;
        QTreeWidgetItem *ti = tree_->topLevelItem(index.row());
        QString interface_name = ti->text(col_interface_);
        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
#ifdef SHOW_BUFFER_COLUMN
            buffer = device.buffer;
#endif
            snap = device.snaplen;
            links = device.links;
            if (interface_name.compare(device.display_name) || device.hidden || device.type == IF_PIPE) {
                continue;
            } else {
                break;
            }
        }
        switch (index.column()) {
        case col_interface_:
        case col_traffic_:
            break;
        case col_link_:
        {
            GList *list;
            link_row *temp;

            if (g_list_length(links) < 2) {
                break;
            }
            QComboBox *cb = new QComboBox(parent);
            for (list=links; list!=NULL; list=g_list_next(list)) {
                temp = (link_row*)(list->data);
                cb->addItem(QString("%1").arg(temp->name));
            }
            connect(cb, SIGNAL(currentIndexChanged(QString)), this, SLOT(link_changed(QString)));
            w = (QWidget*) cb;
            break;
        }
        case col_pmode_:
        {
        // Create the combobox and populate it
            QComboBox *cb = new QComboBox(parent);
            cb->addItem(QString(tr("enabled")));
            cb->addItem(QString(tr("disabled")));
            connect(cb, SIGNAL(currentIndexChanged(QString)), this, SLOT(pmode_changed(QString)));
            w = (QWidget*) cb;
            break;
        }
        case col_snaplen_:
        {
            QSpinBox *sb = new QSpinBox(parent);
            sb->setRange(1, 65535);
            sb->setValue(snap);
            sb->setWrapping(true);
            connect(sb, SIGNAL(valueChanged(int)), this, SLOT(snaplen_changed(int)));
            w = (QWidget*) sb;
            break;
        }
#ifdef SHOW_BUFFER_COLUMN
        case col_buffer_:
        {
            QSpinBox *sb = new QSpinBox(parent);
            sb->setRange(1, 65535);
            sb->setValue(buffer);
            sb->setWrapping(true);
            connect(sb, SIGNAL(valueChanged(int)), this, SLOT(buffer_changed(int)));
            w = (QWidget*) sb;
            break;
        }
#endif
#ifdef SHOW_MONITOR_COLUMN
        case col_monitor_:
        {
             if (index.data().toString().compare(QString("n/a"))) {
                QComboBox *cb = new QComboBox(parent);
                cb->addItem(QString(tr("enabled")));
                cb->addItem(QString(tr("disabled")));
                connect(cb, SIGNAL(currentIndexChanged(QString)), this, SLOT(monitor_changed(QString)));
                w = (QWidget*) cb;
             }
             break;
        }
#endif
        case col_filter_:
        {
            CaptureFilterCombo *cf = new CaptureFilterCombo(parent);
            w = (QWidget*) cf;
        }
        default:
            break;
        }
//        if (w) {
//            ti->setSizeHint(index.column(), w->sizeHint());
//        }
    }
    return w;
}

bool InterfaceTreeDelegate::eventFilter(QObject *object, QEvent *event)
{
    QComboBox * comboBox = dynamic_cast<QComboBox*>(object);
    if (comboBox) {
        if (event->type() == QEvent::MouseButtonRelease) {
            comboBox->showPopup();
            return true;
        }
    } else {
        return QStyledItemDelegate::eventFilter( object, event );
    }
    return false;
}

void InterfaceTreeDelegate::pmode_changed(QString index)
{
    interface_t device;
    guint i;
    QTreeWidgetItem *ti = tree_->currentItem();
    if (!ti) {
        return;
    }
    QString interface_name = ti->text(col_interface_);
    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (interface_name.compare(device.display_name) || device.hidden || device.type == IF_PIPE) {
            continue;
        } else {
            break;
        }
    }
    if (!index.compare(QString(tr("enabled")))) {
        device.pmode = true;
    } else {
        device.pmode = false;
    }

    global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
    g_array_insert_val(global_capture_opts.all_ifaces, i, device);
}

#ifdef SHOW_MONITOR_COLUMN
void InterfaceTreeDelegate::monitor_changed(QString index)
{
    interface_t device;
    guint i;
    QTreeWidgetItem *ti = tree_->currentItem();
    if (!ti) {
        return;
    }
    QString interface_name = ti->text(col_interface_);
    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (interface_name.compare(device.display_name) || device.hidden || device.type == IF_PIPE) {
            continue;
        } else {
            break;
        }
    }
    if (!index.compare(QString(tr("enabled")))) {
        device.monitor_mode_enabled = true;
    } else {
        device.monitor_mode_enabled = false;
    }
    global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
    g_array_insert_val(global_capture_opts.all_ifaces, i, device);
}
#endif

void InterfaceTreeDelegate::link_changed(QString index)
{
    GList *list;
    link_row *temp;
    interface_t device;
    guint i;

    QTreeWidgetItem *ti = tree_->currentItem();
    if (!ti) {
        return;
    }
    QString interface_name = ti->text(col_interface_);
    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (interface_name.compare(device.display_name) || device.hidden || device.type == IF_PIPE) {
            continue;
        } else {
            break;
        }
    }
    for (list = device.links; list != NULL; list = g_list_next(list)) {
        temp = (link_row*) (list->data);
        if (!index.compare(temp->name)) {
            device.active_dlt = temp->dlt;
        }
    }
    global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
    g_array_insert_val(global_capture_opts.all_ifaces, i, device);
}

void InterfaceTreeDelegate::snaplen_changed(int value)
{
    interface_t device;
    guint i;
    QTreeWidgetItem *ti = tree_->currentItem();
    if (!ti) {
        return;
    }
    QString interface_name = ti->text(col_interface_);
    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (interface_name.compare(device.display_name) || device.hidden || device.type == IF_PIPE) {
            continue;
        } else {
            break;
        }
    }
    if (value != WTAP_MAX_PACKET_SIZE) {
        device.has_snaplen = true;
        device.snaplen = value;
    } else {
        device.has_snaplen = false;
        device.snaplen = WTAP_MAX_PACKET_SIZE;
    }
    global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
    g_array_insert_val(global_capture_opts.all_ifaces, i, device);
}

void InterfaceTreeDelegate::buffer_changed(int value)
{
#ifdef SHOW_BUFFER_COLUMN
    interface_t device;
    guint i;
    QTreeWidgetItem *ti = tree_->currentItem();
    if (!ti) {
        return;
    }
    QString interface_name = ti->text(col_interface_);
    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (interface_name.compare(device.display_name) || device.hidden || device.type == IF_PIPE) {
            continue;
        } else {
            break;
        }
    }
    device.buffer = value;
    global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
    g_array_insert_val(global_capture_opts.all_ifaces, i, device);
#endif
}

#endif /* HAVE_LIBPCAP */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

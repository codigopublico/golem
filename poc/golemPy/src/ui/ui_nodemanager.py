# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'manager.ui'
#
# Created: Mon Mar 31 17:35:34 2014
#      by: PyQt4 UI code generator 4.10.3
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

class Ui_NodesManagerWidget(object):
    def setupUi(self, NodesManagerWidget):
        NodesManagerWidget.setObjectName(_fromUtf8("NodesManagerWidget"))
        NodesManagerWidget.resize(1027, 752)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(NodesManagerWidget.sizePolicy().hasHeightForWidth())
        NodesManagerWidget.setSizePolicy(sizePolicy)
        self.horizontalLayout_3 = QtGui.QHBoxLayout(NodesManagerWidget)
        self.horizontalLayout_3.setObjectName(_fromUtf8("horizontalLayout_3"))
        self.verticalLayout = QtGui.QVBoxLayout()
        self.verticalLayout.setContentsMargins(-1, 0, -1, -1)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.label = QtGui.QLabel(NodesManagerWidget)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.label.setFont(font)
        self.label.setObjectName(_fromUtf8("label"))
        self.horizontalLayout.addWidget(self.label)
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.label_6 = QtGui.QLabel(NodesManagerWidget)
        self.label_6.setText(_fromUtf8(""))
        self.label_6.setObjectName(_fromUtf8("label_6"))
        self.horizontalLayout.addWidget(self.label_6)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.horizontalLayout_4 = QtGui.QHBoxLayout()
        self.horizontalLayout_4.setObjectName(_fromUtf8("horizontalLayout_4"))
        self.nodeTableWidget = QtGui.QTableWidget(NodesManagerWidget)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.MinimumExpanding, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.nodeTableWidget.sizePolicy().hasHeightForWidth())
        self.nodeTableWidget.setSizePolicy(sizePolicy)
        self.nodeTableWidget.setMinimumSize(QtCore.QSize(710, 0))
        self.nodeTableWidget.setFrameShape(QtGui.QFrame.Box)
        self.nodeTableWidget.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self.nodeTableWidget.setShowGrid(True)
        self.nodeTableWidget.setRowCount(0)
        self.nodeTableWidget.setColumnCount(4)
        self.nodeTableWidget.setObjectName(_fromUtf8("nodeTableWidget"))
        item = QtGui.QTableWidgetItem()
        self.nodeTableWidget.setHorizontalHeaderItem(0, item)
        item = QtGui.QTableWidgetItem()
        self.nodeTableWidget.setHorizontalHeaderItem(1, item)
        item = QtGui.QTableWidgetItem()
        self.nodeTableWidget.setHorizontalHeaderItem(2, item)
        item = QtGui.QTableWidgetItem()
        self.nodeTableWidget.setHorizontalHeaderItem(3, item)
        self.nodeTableWidget.horizontalHeader().setCascadingSectionResizes(False)
        self.nodeTableWidget.horizontalHeader().setDefaultSectionSize(166)
        self.nodeTableWidget.horizontalHeader().setMinimumSectionSize(27)
        self.nodeTableWidget.verticalHeader().setDefaultSectionSize(22)
        self.horizontalLayout_4.addWidget(self.nodeTableWidget)
        self.verticalLayout_5 = QtGui.QVBoxLayout()
        self.verticalLayout_5.setContentsMargins(0, -1, -1, -1)
        self.verticalLayout_5.setObjectName(_fromUtf8("verticalLayout_5"))
        self.frameDetailedNode = QtGui.QFrame(NodesManagerWidget)
        self.frameDetailedNode.setEnabled(True)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.frameDetailedNode.sizePolicy().hasHeightForWidth())
        self.frameDetailedNode.setSizePolicy(sizePolicy)
        self.frameDetailedNode.setMinimumSize(QtCore.QSize(287, 0))
        self.frameDetailedNode.setFrameShape(QtGui.QFrame.StyledPanel)
        self.frameDetailedNode.setFrameShadow(QtGui.QFrame.Sunken)
        self.frameDetailedNode.setLineWidth(2)
        self.frameDetailedNode.setMidLineWidth(1)
        self.frameDetailedNode.setObjectName(_fromUtf8("frameDetailedNode"))
        self.horizontalLayout_6 = QtGui.QHBoxLayout(self.frameDetailedNode)
        self.horizontalLayout_6.setObjectName(_fromUtf8("horizontalLayout_6"))
        self.verticalLayout_2 = QtGui.QVBoxLayout()
        self.verticalLayout_2.setMargin(0)
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))
        self.line_2 = QtGui.QFrame(self.frameDetailedNode)
        self.line_2.setFrameShape(QtGui.QFrame.HLine)
        self.line_2.setFrameShadow(QtGui.QFrame.Sunken)
        self.line_2.setObjectName(_fromUtf8("line_2"))
        self.verticalLayout_2.addWidget(self.line_2)
        self.labelDetailedNode = QtGui.QLabel(self.frameDetailedNode)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.labelDetailedNode.setFont(font)
        self.labelDetailedNode.setObjectName(_fromUtf8("labelDetailedNode"))
        self.verticalLayout_2.addWidget(self.labelDetailedNode)
        self.verticalLayout_3 = QtGui.QVBoxLayout()
        self.verticalLayout_3.setContentsMargins(10, 0, 0, 0)
        self.verticalLayout_3.setObjectName(_fromUtf8("verticalLayout_3"))
        self.gridLayout_2 = QtGui.QGridLayout()
        self.gridLayout_2.setObjectName(_fromUtf8("gridLayout_2"))
        self.label_8 = QtGui.QLabel(self.frameDetailedNode)
        self.label_8.setObjectName(_fromUtf8("label_8"))
        self.gridLayout_2.addWidget(self.label_8, 1, 0, 1, 1)
        self.label_7 = QtGui.QLabel(self.frameDetailedNode)
        self.label_7.setMinimumSize(QtCore.QSize(0, 0))
        self.label_7.setObjectName(_fromUtf8("label_7"))
        self.gridLayout_2.addWidget(self.label_7, 0, 0, 1, 1)
        self.endpointInput = QtGui.QLineEdit(self.frameDetailedNode)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.endpointInput.sizePolicy().hasHeightForWidth())
        self.endpointInput.setSizePolicy(sizePolicy)
        self.endpointInput.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.endpointInput.setText(_fromUtf8(""))
        self.endpointInput.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.endpointInput.setReadOnly(True)
        self.endpointInput.setObjectName(_fromUtf8("endpointInput"))
        self.gridLayout_2.addWidget(self.endpointInput, 0, 1, 1, 1)
        self.noPeersInput = QtGui.QLineEdit(self.frameDetailedNode)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.noPeersInput.sizePolicy().hasHeightForWidth())
        self.noPeersInput.setSizePolicy(sizePolicy)
        self.noPeersInput.setText(_fromUtf8(""))
        self.noPeersInput.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.noPeersInput.setReadOnly(True)
        self.noPeersInput.setObjectName(_fromUtf8("noPeersInput"))
        self.gridLayout_2.addWidget(self.noPeersInput, 1, 1, 1, 1)
        self.noTasksInput = QtGui.QLineEdit(self.frameDetailedNode)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.noTasksInput.sizePolicy().hasHeightForWidth())
        self.noTasksInput.setSizePolicy(sizePolicy)
        self.noTasksInput.setText(_fromUtf8(""))
        self.noTasksInput.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.noTasksInput.setReadOnly(True)
        self.noTasksInput.setObjectName(_fromUtf8("noTasksInput"))
        self.gridLayout_2.addWidget(self.noTasksInput, 2, 1, 1, 1)
        self.label_9 = QtGui.QLabel(self.frameDetailedNode)
        self.label_9.setObjectName(_fromUtf8("label_9"))
        self.gridLayout_2.addWidget(self.label_9, 2, 0, 1, 1)
        self.label_10 = QtGui.QLabel(self.frameDetailedNode)
        self.label_10.setObjectName(_fromUtf8("label_10"))
        self.gridLayout_2.addWidget(self.label_10, 3, 0, 1, 1)
        self.lastMsgInput = QtGui.QLineEdit(self.frameDetailedNode)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.lastMsgInput.sizePolicy().hasHeightForWidth())
        self.lastMsgInput.setSizePolicy(sizePolicy)
        self.lastMsgInput.setText(_fromUtf8(""))
        self.lastMsgInput.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.lastMsgInput.setReadOnly(True)
        self.lastMsgInput.setObjectName(_fromUtf8("lastMsgInput"))
        self.gridLayout_2.addWidget(self.lastMsgInput, 3, 1, 1, 1)
        self.verticalLayout_3.addLayout(self.gridLayout_2)
        self.verticalLayout_2.addLayout(self.verticalLayout_3)
        self.line = QtGui.QFrame(self.frameDetailedNode)
        self.line.setFrameShape(QtGui.QFrame.HLine)
        self.line.setFrameShadow(QtGui.QFrame.Sunken)
        self.line.setObjectName(_fromUtf8("line"))
        self.verticalLayout_2.addWidget(self.line)
        self.labelDetailedRemoteTask = QtGui.QLabel(self.frameDetailedNode)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.labelDetailedRemoteTask.setFont(font)
        self.labelDetailedRemoteTask.setObjectName(_fromUtf8("labelDetailedRemoteTask"))
        self.verticalLayout_2.addWidget(self.labelDetailedRemoteTask)
        self.verticalLayout_4 = QtGui.QVBoxLayout()
        self.verticalLayout_4.setContentsMargins(10, -1, -1, -1)
        self.verticalLayout_4.setObjectName(_fromUtf8("verticalLayout_4"))
        self.gridLayout = QtGui.QGridLayout()
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.label_4 = QtGui.QLabel(self.frameDetailedNode)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_4.sizePolicy().hasHeightForWidth())
        self.label_4.setSizePolicy(sizePolicy)
        self.label_4.setObjectName(_fromUtf8("label_4"))
        self.gridLayout.addWidget(self.label_4, 2, 0, 1, 1)
        self.timeLeftInput = QtGui.QLineEdit(self.frameDetailedNode)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.timeLeftInput.sizePolicy().hasHeightForWidth())
        self.timeLeftInput.setSizePolicy(sizePolicy)
        self.timeLeftInput.setText(_fromUtf8(""))
        self.timeLeftInput.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.timeLeftInput.setReadOnly(True)
        self.timeLeftInput.setObjectName(_fromUtf8("timeLeftInput"))
        self.gridLayout.addWidget(self.timeLeftInput, 2, 1, 1, 1)
        self.label_2 = QtGui.QLabel(self.frameDetailedNode)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_2.sizePolicy().hasHeightForWidth())
        self.label_2.setSizePolicy(sizePolicy)
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.gridLayout.addWidget(self.label_2, 1, 0, 1, 1)
        self.cpuPowerInput = QtGui.QLineEdit(self.frameDetailedNode)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.cpuPowerInput.sizePolicy().hasHeightForWidth())
        self.cpuPowerInput.setSizePolicy(sizePolicy)
        self.cpuPowerInput.setText(_fromUtf8(""))
        self.cpuPowerInput.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.cpuPowerInput.setReadOnly(True)
        self.cpuPowerInput.setObjectName(_fromUtf8("cpuPowerInput"))
        self.gridLayout.addWidget(self.cpuPowerInput, 1, 1, 1, 1)
        self.label_3 = QtGui.QLabel(self.frameDetailedNode)
        self.label_3.setObjectName(_fromUtf8("label_3"))
        self.gridLayout.addWidget(self.label_3, 3, 0, 1, 1)
        self.activeChunkProgressBar = QtGui.QProgressBar(self.frameDetailedNode)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.activeChunkProgressBar.sizePolicy().hasHeightForWidth())
        self.activeChunkProgressBar.setSizePolicy(sizePolicy)
        self.activeChunkProgressBar.setMinimumSize(QtCore.QSize(160, 0))
        self.activeChunkProgressBar.setProperty("value", 0)
        self.activeChunkProgressBar.setObjectName(_fromUtf8("activeChunkProgressBar"))
        self.gridLayout.addWidget(self.activeChunkProgressBar, 3, 1, 1, 1)
        self.label_11 = QtGui.QLabel(self.frameDetailedNode)
        self.label_11.setObjectName(_fromUtf8("label_11"))
        self.gridLayout.addWidget(self.label_11, 0, 0, 1, 1)
        self.chunkShortDescrInput = QtGui.QLineEdit(self.frameDetailedNode)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.chunkShortDescrInput.sizePolicy().hasHeightForWidth())
        self.chunkShortDescrInput.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(7)
        self.chunkShortDescrInput.setFont(font)
        self.chunkShortDescrInput.setReadOnly(True)
        self.chunkShortDescrInput.setObjectName(_fromUtf8("chunkShortDescrInput"))
        self.gridLayout.addWidget(self.chunkShortDescrInput, 0, 1, 1, 1)
        self.verticalLayout_4.addLayout(self.gridLayout)
        self.verticalLayout_2.addLayout(self.verticalLayout_4)
        self.line_3 = QtGui.QFrame(self.frameDetailedNode)
        self.line_3.setFrameShape(QtGui.QFrame.HLine)
        self.line_3.setFrameShadow(QtGui.QFrame.Sunken)
        self.line_3.setObjectName(_fromUtf8("line_3"))
        self.verticalLayout_2.addWidget(self.line_3)
        self.labelDetailedLocalTask = QtGui.QLabel(self.frameDetailedNode)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.labelDetailedLocalTask.setFont(font)
        self.labelDetailedLocalTask.setObjectName(_fromUtf8("labelDetailedLocalTask"))
        self.verticalLayout_2.addWidget(self.labelDetailedLocalTask)
        self.gridLayout_3 = QtGui.QGridLayout()
        self.gridLayout_3.setContentsMargins(10, 0, -1, -1)
        self.gridLayout_3.setObjectName(_fromUtf8("gridLayout_3"))
        self.allocatedTasksInput = QtGui.QLineEdit(self.frameDetailedNode)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.allocatedTasksInput.sizePolicy().hasHeightForWidth())
        self.allocatedTasksInput.setSizePolicy(sizePolicy)
        self.allocatedTasksInput.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.allocatedTasksInput.setReadOnly(True)
        self.allocatedTasksInput.setObjectName(_fromUtf8("allocatedTasksInput"))
        self.gridLayout_3.addWidget(self.allocatedTasksInput, 1, 1, 1, 1)
        self.label_12 = QtGui.QLabel(self.frameDetailedNode)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_12.sizePolicy().hasHeightForWidth())
        self.label_12.setSizePolicy(sizePolicy)
        self.label_12.setObjectName(_fromUtf8("label_12"))
        self.gridLayout_3.addWidget(self.label_12, 1, 0, 1, 1)
        self.localTaskProgressBar = QtGui.QProgressBar(self.frameDetailedNode)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.localTaskProgressBar.sizePolicy().hasHeightForWidth())
        self.localTaskProgressBar.setSizePolicy(sizePolicy)
        self.localTaskProgressBar.setMinimumSize(QtCore.QSize(160, 0))
        self.localTaskProgressBar.setProperty("value", 0)
        self.localTaskProgressBar.setObjectName(_fromUtf8("localTaskProgressBar"))
        self.gridLayout_3.addWidget(self.localTaskProgressBar, 6, 1, 1, 1)
        self.label_13 = QtGui.QLabel(self.frameDetailedNode)
        self.label_13.setObjectName(_fromUtf8("label_13"))
        self.gridLayout_3.addWidget(self.label_13, 2, 0, 1, 1)
        self.label_14 = QtGui.QLabel(self.frameDetailedNode)
        self.label_14.setObjectName(_fromUtf8("label_14"))
        self.gridLayout_3.addWidget(self.label_14, 3, 0, 1, 1)
        self.label_15 = QtGui.QLabel(self.frameDetailedNode)
        self.label_15.setObjectName(_fromUtf8("label_15"))
        self.gridLayout_3.addWidget(self.label_15, 4, 0, 1, 1)
        self.label_16 = QtGui.QLabel(self.frameDetailedNode)
        self.label_16.setObjectName(_fromUtf8("label_16"))
        self.gridLayout_3.addWidget(self.label_16, 5, 0, 1, 1)
        self.allocatedChunksInput = QtGui.QLineEdit(self.frameDetailedNode)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.allocatedChunksInput.sizePolicy().hasHeightForWidth())
        self.allocatedChunksInput.setSizePolicy(sizePolicy)
        self.allocatedChunksInput.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.allocatedChunksInput.setReadOnly(True)
        self.allocatedChunksInput.setObjectName(_fromUtf8("allocatedChunksInput"))
        self.gridLayout_3.addWidget(self.allocatedChunksInput, 2, 1, 1, 1)
        self.activeTasksInput = QtGui.QLineEdit(self.frameDetailedNode)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.activeTasksInput.sizePolicy().hasHeightForWidth())
        self.activeTasksInput.setSizePolicy(sizePolicy)
        self.activeTasksInput.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.activeTasksInput.setReadOnly(True)
        self.activeTasksInput.setObjectName(_fromUtf8("activeTasksInput"))
        self.gridLayout_3.addWidget(self.activeTasksInput, 3, 1, 1, 1)
        self.activeChunksInput = QtGui.QLineEdit(self.frameDetailedNode)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.activeChunksInput.sizePolicy().hasHeightForWidth())
        self.activeChunksInput.setSizePolicy(sizePolicy)
        self.activeChunksInput.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.activeChunksInput.setReadOnly(True)
        self.activeChunksInput.setObjectName(_fromUtf8("activeChunksInput"))
        self.gridLayout_3.addWidget(self.activeChunksInput, 4, 1, 1, 1)
        self.chunksLeftInput = QtGui.QLineEdit(self.frameDetailedNode)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.chunksLeftInput.sizePolicy().hasHeightForWidth())
        self.chunksLeftInput.setSizePolicy(sizePolicy)
        self.chunksLeftInput.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.chunksLeftInput.setReadOnly(True)
        self.chunksLeftInput.setObjectName(_fromUtf8("chunksLeftInput"))
        self.gridLayout_3.addWidget(self.chunksLeftInput, 5, 1, 1, 1)
        self.label_17 = QtGui.QLabel(self.frameDetailedNode)
        self.label_17.setObjectName(_fromUtf8("label_17"))
        self.gridLayout_3.addWidget(self.label_17, 0, 0, 1, 1)
        self.locTaskShortDescrInput = QtGui.QLineEdit(self.frameDetailedNode)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.locTaskShortDescrInput.sizePolicy().hasHeightForWidth())
        self.locTaskShortDescrInput.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(7)
        self.locTaskShortDescrInput.setFont(font)
        self.locTaskShortDescrInput.setObjectName(_fromUtf8("locTaskShortDescrInput"))
        self.gridLayout_3.addWidget(self.locTaskShortDescrInput, 0, 1, 1, 1)
        self.verticalLayout_2.addLayout(self.gridLayout_3)
        self.horizontalLayout_7 = QtGui.QHBoxLayout()
        self.horizontalLayout_7.setContentsMargins(-1, 10, -1, -1)
        self.horizontalLayout_7.setObjectName(_fromUtf8("horizontalLayout_7"))
        spacerItem1 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.MinimumExpanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_7.addItem(spacerItem1)
        self.enqueueTaskButton = QtGui.QPushButton(self.frameDetailedNode)
        self.enqueueTaskButton.setMinimumSize(QtCore.QSize(120, 0))
        self.enqueueTaskButton.setMaximumSize(QtCore.QSize(120, 16777215))
        self.enqueueTaskButton.setObjectName(_fromUtf8("enqueueTaskButton"))
        self.horizontalLayout_7.addWidget(self.enqueueTaskButton)
        self.verticalLayout_2.addLayout(self.horizontalLayout_7)
        self.line_5 = QtGui.QFrame(self.frameDetailedNode)
        self.line_5.setFrameShape(QtGui.QFrame.HLine)
        self.line_5.setFrameShadow(QtGui.QFrame.Sunken)
        self.line_5.setObjectName(_fromUtf8("line_5"))
        self.verticalLayout_2.addWidget(self.line_5)
        self.horizontalLayout_5 = QtGui.QHBoxLayout()
        self.horizontalLayout_5.setContentsMargins(-1, 0, -1, -1)
        self.horizontalLayout_5.setObjectName(_fromUtf8("horizontalLayout_5"))
        self.stopNodePushButton = QtGui.QPushButton(self.frameDetailedNode)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.stopNodePushButton.sizePolicy().hasHeightForWidth())
        self.stopNodePushButton.setSizePolicy(sizePolicy)
        self.stopNodePushButton.setMinimumSize(QtCore.QSize(120, 0))
        self.stopNodePushButton.setMaximumSize(QtCore.QSize(12567, 16777215))
        self.stopNodePushButton.setObjectName(_fromUtf8("stopNodePushButton"))
        self.horizontalLayout_5.addWidget(self.stopNodePushButton)
        self.verticalLayout_2.addLayout(self.horizontalLayout_5)
        self.horizontalLayout_6.addLayout(self.verticalLayout_2)
        self.verticalLayout_5.addWidget(self.frameDetailedNode)
        self.frameGenericNodes = QtGui.QFrame(NodesManagerWidget)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.frameGenericNodes.sizePolicy().hasHeightForWidth())
        self.frameGenericNodes.setSizePolicy(sizePolicy)
        self.frameGenericNodes.setMinimumSize(QtCore.QSize(287, 75))
        self.frameGenericNodes.setFrameShape(QtGui.QFrame.StyledPanel)
        self.frameGenericNodes.setFrameShadow(QtGui.QFrame.Sunken)
        self.frameGenericNodes.setObjectName(_fromUtf8("frameGenericNodes"))
        self.verticalLayout_6 = QtGui.QVBoxLayout(self.frameGenericNodes)
        self.verticalLayout_6.setObjectName(_fromUtf8("verticalLayout_6"))
        self.verticalLayout_7 = QtGui.QVBoxLayout()
        self.verticalLayout_7.setContentsMargins(-1, 0, -1, -1)
        self.verticalLayout_7.setObjectName(_fromUtf8("verticalLayout_7"))
        self.horizontalLayout_8 = QtGui.QHBoxLayout()
        self.horizontalLayout_8.setObjectName(_fromUtf8("horizontalLayout_8"))
        self.runAdditionalNodesPushButton = QtGui.QPushButton(self.frameGenericNodes)
        self.runAdditionalNodesPushButton.setMinimumSize(QtCore.QSize(220, 23))
        self.runAdditionalNodesPushButton.setObjectName(_fromUtf8("runAdditionalNodesPushButton"))
        self.horizontalLayout_8.addWidget(self.runAdditionalNodesPushButton)
        self.additionalNodesSpinBox = QtGui.QSpinBox(self.frameGenericNodes)
        self.additionalNodesSpinBox.setProperty("value", 4)
        self.additionalNodesSpinBox.setObjectName(_fromUtf8("additionalNodesSpinBox"))
        self.horizontalLayout_8.addWidget(self.additionalNodesSpinBox)
        self.verticalLayout_7.addLayout(self.horizontalLayout_8)
        self.terminateAllNodesPushButton = QtGui.QPushButton(self.frameGenericNodes)
        self.terminateAllNodesPushButton.setMinimumSize(QtCore.QSize(0, 23))
        self.terminateAllNodesPushButton.setObjectName(_fromUtf8("terminateAllNodesPushButton"))
        self.verticalLayout_7.addWidget(self.terminateAllNodesPushButton)
        self.verticalLayout_6.addLayout(self.verticalLayout_7)
        self.verticalLayout_5.addWidget(self.frameGenericNodes)
        self.horizontalLayout_4.addLayout(self.verticalLayout_5)
        self.verticalLayout.addLayout(self.horizontalLayout_4)
        self.line_4 = QtGui.QFrame(NodesManagerWidget)
        self.line_4.setFrameShape(QtGui.QFrame.HLine)
        self.line_4.setFrameShadow(QtGui.QFrame.Sunken)
        self.line_4.setObjectName(_fromUtf8("line_4"))
        self.verticalLayout.addWidget(self.line_4)
        self.horizontalLayout_2 = QtGui.QHBoxLayout()
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
        spacerItem2 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem2)
        self.label_5 = QtGui.QLabel(NodesManagerWidget)
        font = QtGui.QFont()
        font.setItalic(True)
        self.label_5.setFont(font)
        self.label_5.setObjectName(_fromUtf8("label_5"))
        self.horizontalLayout_2.addWidget(self.label_5)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_3.addLayout(self.verticalLayout)

        self.retranslateUi(NodesManagerWidget)
        QtCore.QMetaObject.connectSlotsByName(NodesManagerWidget)

    def retranslateUi(self, NodesManagerWidget):
        NodesManagerWidget.setWindowTitle(_translate("NodesManagerWidget", "Node manager", None))
        self.label.setText(_translate("NodesManagerWidget", "List of nodes running locally", None))
        item = self.nodeTableWidget.horizontalHeaderItem(0)
        item.setText(_translate("NodesManagerWidget", "Node", None))
        item = self.nodeTableWidget.horizontalHeaderItem(1)
        item.setText(_translate("NodesManagerWidget", "Last seen", None))
        item = self.nodeTableWidget.horizontalHeaderItem(2)
        item.setText(_translate("NodesManagerWidget", "Remote Task", None))
        item = self.nodeTableWidget.horizontalHeaderItem(3)
        item.setText(_translate("NodesManagerWidget", "Local task", None))
        self.labelDetailedNode.setText(_translate("NodesManagerWidget", "Node (UID)", None))
        self.label_8.setText(_translate("NodesManagerWidget", "No. peers", None))
        self.label_7.setText(_translate("NodesManagerWidget", "Endpoint", None))
        self.label_9.setText(_translate("NodesManagerWidget", "No. tasks", None))
        self.label_10.setText(_translate("NodesManagerWidget", "Last msg.", None))
        self.labelDetailedRemoteTask.setText(_translate("NodesManagerWidget", "Active task chunk (ID)", None))
        self.label_4.setText(_translate("NodesManagerWidget", "Time left", None))
        self.label_2.setText(_translate("NodesManagerWidget", "CPU power", None))
        self.label_3.setText(_translate("NodesManagerWidget", "Progress", None))
        self.label_11.setText(_translate("NodesManagerWidget", "Short description", None))
        self.labelDetailedLocalTask.setText(_translate("NodesManagerWidget", "Active local task (ID)", None))
        self.label_12.setText(_translate("NodesManagerWidget", "Allocated tasks", None))
        self.label_13.setText(_translate("NodesManagerWidget", "Allocated chunks", None))
        self.label_14.setText(_translate("NodesManagerWidget", "Active tasks", None))
        self.label_15.setText(_translate("NodesManagerWidget", "Active chunks", None))
        self.label_16.setText(_translate("NodesManagerWidget", "Chunks left", None))
        self.label_17.setText(_translate("NodesManagerWidget", "Short description", None))
        self.enqueueTaskButton.setText(_translate("NodesManagerWidget", "Enqueue task", None))
        self.stopNodePushButton.setText(_translate("NodesManagerWidget", "Stop node", None))
        self.runAdditionalNodesPushButton.setText(_translate("NodesManagerWidget", "Run additional local nodes", None))
        self.terminateAllNodesPushButton.setText(_translate("NodesManagerWidget", "Terminate all local nodes", None))
        self.label_5.setText(_translate("NodesManagerWidget", "GoLEM POC manager", None))


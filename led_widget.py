#!/usr/bin/python3
# -*- coding: utf-8 -*-

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtCore import Qt


class LedIndicator(QtWidgets.QAbstractButton):
	scaledSize = 1000.0

	def __init__(self, parent=None, color=[[0, 255, 0],[0, 192, 0],[0, 28, 0],[0, 128, 0]]):
		QtWidgets.QAbstractButton.__init__(self, parent)

		self.setMinimumSize(24, 24)
		self.setCheckable(True)

		# Green
		self.on_color_1 = QtGui.QColor(color[0][0],color[0][1],color[0][2])
		self.on_color_2 = QtGui.QColor(color[1][0],color[1][1],color[1][2])
		self.off_color_1 = QtGui.QColor(color[2][0],color[2][1],color[2][2])
		self.off_color_2 = QtGui.QColor(color[3][0],color[3][1],color[3][2])

	def resizeEvent(self, QResizeEvent):
		self.update()

	def paintEvent(self, QPaintEvent):
		realSize = min(self.width(), self.height())

		painter = QtGui.QPainter(self)
		pen = QtGui.QPen(Qt.black)
		pen.setWidth(1)

		painter.setRenderHint(QtGui.QPainter.Antialiasing)
		painter.translate(self.width() / 2, self.height() / 2)
		painter.scale(realSize / self.scaledSize, realSize / self.scaledSize)

		gradient = QtGui.QRadialGradient(QtCore.QPointF(-500, -500), 1500, QtCore.QPointF(-500, -500))
		gradient.setColorAt(0, QtGui.QColor(224, 224, 224))
		gradient.setColorAt(1, QtGui.QColor(28, 28, 28))
		painter.setPen(pen)
		painter.setBrush(QtGui.QBrush(gradient))
		painter.drawEllipse(QtCore.QPointF(0, 0), 500, 500)

		gradient = QtGui.QRadialGradient(QtCore.QPointF(500, 500), 1500, QtCore.QPointF(500, 500))
		gradient.setColorAt(0, QtGui.QColor(224, 224, 224))
		gradient.setColorAt(1, QtGui.QColor(28, 28, 28))
		painter.setPen(pen)
		painter.setBrush(QtGui.QBrush(gradient))
		painter.drawEllipse(QtCore.QPointF(0, 0), 450, 450)

		painter.setPen(pen)
		if self.isChecked():
			gradient = QtGui.QRadialGradient(QtCore.QPointF(-500, -500), 1500, QtCore.QPointF(-500, -500))
			gradient.setColorAt(0, self.on_color_1)
			gradient.setColorAt(1, self.on_color_2)
		else:
			gradient = QtGui.QRadialGradient(QtCore.QPointF(500, 500), 1500, QtCore.QPointF(500, 500))
			gradient.setColorAt(0, self.off_color_1)
			gradient.setColorAt(1, self.off_color_2)

		painter.setBrush(gradient)
		painter.drawEllipse(QtCore.QPointF(0, 0), 400, 400)

	@QtCore.pyqtProperty(QtGui.QColor)
	def onColor1(self):
		return self.on_color_1

	@onColor1.setter
	def onColor1(self, color):
		self.on_color_1 = color

	@QtCore.pyqtProperty(QtGui.QColor)
	def onColor2(self):
		return self.on_color_2

	@onColor2.setter
	def onColor2(self, color):
		self.on_color_2 = color

	@QtCore.pyqtProperty(QtGui.QColor)
	def offColor1(self):
		return self.off_color_1

	@offColor1.setter
	def offColor1(self, color):
		self.off_color_1 = color

	@QtCore.pyqtProperty(QtGui.QColor)
	def offColor2(self):
		return self.off_color_2

	@offColor2.setter
	def offColor2(self, color):
		self.off_color_2 = color

const express = require('express');
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// تهيئة Firebase
admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
  })
});
const db = admin.firestore();

// تهيئة البريد الإلكتروني
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// حماية من الهجمات
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

// ============= دالة التحقق من JWT =============
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'غير مصرح' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'توكن غير صالح' });
  }
};

// ============= API إنشاء حساب طالب =============
app.post('/api/student/register', async (req, res) => {
  const { studentId, name, email, password, className, parentPhone } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    await db.collection('students').doc(studentId).set({
      name, email, password: hashedPassword, className, parentPhone,
      createdAt: new Date()
    });
    res.json({ success: true, message: 'تم إنشاء حساب الطالب' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============= API تسجيل دخول طالب =============
app.post('/api/student/login', async (req, res) => {
  const { studentId, password } = req.body;

  try {
    const studentDoc = await db.collection('students').doc(studentId).get();

    if (!studentDoc.exists) {
      return res.status(401).json({ error: 'بيانات غير صحيحة' });
    }

    const student = studentDoc.data();
    const valid = await bcrypt.compare(password, student.password);

    if (!valid) {
      return res.status(401).json({ error: 'بيانات غير صحيحة' });
    }

    const token = jwt.sign(
      { id: studentId, role: 'student', name: student.name },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      student: {
        id: studentId,
        name: student.name,
        className: student.className
      }
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============= API تسجيل حضور/غياب =============
app.post('/api/attendance', verifyToken, async (req, res) => {
  const { studentId, status, date, note } = req.body;

  if (!studentId || !status || !date) {
    return res.status(400).json({ error: 'بيانات ناقصة' });
  }

  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'الحضور من الإدارة فقط' });
  }

  try {
    await db.collection('attendance').doc(`${studentId}_${date}`).set({
      studentId,
      status,
      date,
      note: status === 'absent' ? (note || '') : '',
      recordedBy: req.user.id,
      timestamp: new Date()
    });

    // ✅ جلب الطالب
    const studentDoc = await db.collection('students').doc(studentId).get();
    const student = studentDoc.data();

    // ✅ جلب ولي الأمر بالهاتف
    const parentQuery = await db.collection('parents')
      .where('phone', '==', student.parentPhone)
      .get();

    if (!parentQuery.empty) {
      const parent = parentQuery.docs[0].data();

      await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: parent.email,
        subject: `حضور/غياب الطالب ${student.name}`,
        text: `الطالب ${student.name} تم تسجيله ${status === 'present' ? 'حاضر' : 'غائب'} بتاريخ ${date} ${note ? `\nملاحظة: ${note}` : ''}`
      });
    }

    res.json({ success: true, message: 'تم تسجيل الحضور/الغياب' });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/student/reinstate', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'غير مصرح' });
  }

  try {
    const { studentId } = req.body;

    await db.collection('students').doc(studentId).update({
      status: 'active'
    });

    const student = await db.collection('students').doc(studentId).get();

    if (student.exists) {
      const data = student.data();

      await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: data.email,
        subject: 'إعادة قيد الطالب',
        text: `تم إعادة قيد الطالب ${data.name} في المدرسة`
      });
    }

    res.json({ success: true });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/student/me', verifyToken, async (req, res) => {
  try {
    const studentDoc = await db.collection('students').doc(req.user.id).get();

    if (!studentDoc.exists) {
      return res.status(404).json({ error: 'غير موجود' });
    }

    const student = studentDoc.data();

    res.json({
      success: true,
      student: {
        id: req.user.id,
        name: student.name,
        className: student.className,
        status: student.status || 'active'
      }
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/student/dismiss', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'غير مصرح' });
  }

  try {
    const { studentId } = req.body;

    await db.collection('students').doc(studentId).update({
      status: 'dismissed'
    });

    // إرسال ايميل
    const student = await db.collection('students').doc(studentId).get();

    if (student.exists) {
      const data = student.data();

      await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: data.email,
        subject: 'تم فصل الطالب من المدرسة',
        text: `تم فصل الطالب ${data.name} من المدرسة`
      });
    }

    res.json({ success: true });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
// ============= API جلب تقرير الطالب =============
app.get('/api/student/:id/report', verifyToken, async (req, res) => {
  if (req.user.id !== req.params.id && req.user.role !== 'parent' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'غير مصرح' });
  }
  const attendance = await db.collection('attendance').where('studentId', '==', req.params.id).get();
  const reports = attendance.docs.map(doc => doc.data());
  res.json({ success: true, reports });
});

// ============= API إنشاء حساب ولي أمر =============
app.post('/api/parent/register', async (req, res) => {
  const { email, password, name, phone, studentIds } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    await db.collection('parents').doc(email).set({
      email, password: hashedPassword, name, phone, studentIds, createdAt: new Date()
    });
    res.json({ success: true, message: 'تم إنشاء حساب ولي الأمر' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============= API تسجيل دخول ولي أمر =============
app.post('/api/parent/login', async (req, res) => {
  const { phone, password } = req.body;

  try {
    const snapshot = await db.collection('parents')
      .where('phone', '==', phone)
      .get();

    if (snapshot.empty) {
      return res.status(401).json({ error: 'بيانات غير صحيحة' });
    }

    const parentDoc = snapshot.docs[0];
    const parent = parentDoc.data();

    const valid = await bcrypt.compare(password, parent.password);
    if (!valid) {
      return res.status(401).json({ error: 'بيانات غير صحيحة' });
    }

    const token = jwt.sign(
      { id: parentDoc.id, role: 'parent', name: parent.name },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      parent: {
        phone: parent.phone,
        name: parent.name,
        studentIds: parent.studentIds
      }
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============= API دخول الأدمن =============
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === process.env.ADMIN_USER && password === process.env.ADMIN_PASS) {
    const token = jwt.sign({ id: 'admin', role: 'admin', name: 'مدير المدرسة' }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ success: true, token });
  } else {
    res.status(401).json({ error: 'بيانات المدير غير صحيحة' });
  }
});

app.put('/api/admin/student/:id', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'غير مصرح' });
  }

  try {
    const studentId = req.params.id;

    const docRef = db.collection('students').doc(studentId);
    const doc = await docRef.get();

    if (!doc.exists) {
      return res.status(404).json({ error: 'الطالب غير موجود' });
    }

    const {
      studentId,
      name,
      email,
      password,
      className,
      parentPhone
    } = req.body;

    const updateData = {};

    if (studentId !== undefined) updateData.studentId = studentId;
    if (name !== undefined) updateData.name = name;
    if (email !== undefined) updateData.email = email;
    if (className !== undefined) updateData.className = className;
    if (parentPhone !== undefined) updateData.parentPhone = parentPhone;

    if (password && password.trim() !== '') {
      updateData.password = await bcrypt.hash(password, 10);
    }

    await docRef.update(updateData);

    res.json({ success: true, message: 'تم تحديث بيانات الطالب' });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============= API جلب كل الطلاب للأدمن =============
app.get('/api/admin/students', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'غير مصرح' });
  const students = await db.collection('students').get();
  const list = students.docs.map(doc => ({ id: doc.id, ...doc.data(), password: undefined }));
  res.json({ success: true, students: list });
});

// ============= API جلب كل الحضور للأدمن =============
app.get('/api/admin/attendance', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'غير مصرح' });
  const attendance = await db.collection('attendance').get();
  const list = attendance.docs.map(doc => doc.data());
  res.json({ success: true, attendance: list });
});

app.get('/api/test', (req, res) => {
  res.json({ ok: true, message: "server is working" });
});

// بدء الخادم
module.exports = app;

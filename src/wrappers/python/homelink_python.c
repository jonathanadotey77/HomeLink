#include <homelink_client.h>

#include <Python.h>

#define UNUSED(x) (void)(x)

static PyObject *_getHostKey(PyObject *self)
{
    UNUSED(self);

    const char *hostKey = getHostKey();
    return PyUnicode_FromString(hostKey);
}

static struct PyMethodDef homelinkMethods[] = {{"getHostKey", (PyCFunction)_getHostKey, METH_NOARGS, "Returns the host key."}, {NULL, NULL, 0, NULL}};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT,
    "_homelink_python_c_extension",
    NULL,
    -1,
    homelinkMethods};

PyMODINIT_FUNC PyInit__homelink_python_c_extension(void)
{
    return PyModule_Create(&module);
}
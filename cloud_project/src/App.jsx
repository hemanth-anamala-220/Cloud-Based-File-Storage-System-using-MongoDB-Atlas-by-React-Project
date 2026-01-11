import React, { useState, useEffect } from 'react';
import { LogOut, Search } from 'lucide-react';
import './App.css';

const API_URL = 'https://cloud-based-file-storage-system-using.onrender.com';

// Auth Context
const AuthContext = React.createContext(null);

const useAuth = () => {
  const context = React.useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
};

const AuthProvider = ({ children }) => {
  const [authToken, setAuthToken] = useState(localStorage.getItem('authToken'));
  const [currentUser, setCurrentUser] = useState(
    JSON.parse(localStorage.getItem('currentUser') || 'null')
  );

  const login = (token, user) => {
    setAuthToken(token);
    setCurrentUser(user);
    localStorage.setItem('authToken', token);
    localStorage.setItem('currentUser', JSON.stringify(user));
  };

  const logout = () => {
    setAuthToken(null);
    setCurrentUser(null);
    localStorage.removeItem('authToken');
    localStorage.removeItem('currentUser');
  };

  return (
    <AuthContext.Provider value={{ authToken, currentUser, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

// Login Component
const LoginForm = ({ onSwitchToRegister }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const { login } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!email || !password) {
      setError('Please fill in all fields');
      return;
    }

    try {
      const response = await fetch(`${API_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();

      if (response.ok && data.success) {
        login(data.token, data.user);
      } else {
        setError(data.error || 'Login failed');
      }
    } catch (err) {
      setError('Login error: ' + err.message);
    }
  };

  return (
    <div className="auth-form">
      <h2>🔐 Login to Cloud Storage</h2>
      {error && <div className="error-message">{error}</div>}
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label>Email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Enter your email"
          />
        </div>
        <div className="form-group">
          <label>Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter your password"
          />
        </div>
        <button type="submit" className="btn">Login</button>
        <div className="switch-auth">
          Don't have an account?{' '}
          <a onClick={onSwitchToRegister}>Register</a>
        </div>
        <div className="auth-copyright">
          <p>© 2025 Hemanth Anamala</p>
          <p>All Rights Reserved</p>
        </div>
      </form>
    </div>
  );
};

// Register Component
const RegisterForm = ({ onSwitchToLogin }) => {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const { login } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!name || !email || !password) {
      setError('Please fill in all fields');
      return;
    }

    try {
      const response = await fetch(`${API_URL}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password })
      });

      const data = await response.json();

      if (response.ok && data.success) {
        login(data.token, data.user);
      } else {
        setError(data.error || 'Registration failed');
      }
    } catch (err) {
      setError('Registration error: ' + err.message);
    }
  };

  return (
    <div className="auth-form">
      <h2>📝 Create Account</h2>
      {error && <div className="error-message">{error}</div>}
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label>Name</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Enter your name"
          />
        </div>
        <div className="form-group">
          <label>Email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Enter your email"
          />
        </div>
        <div className="form-group">
          <label>Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Create a password"
          />
        </div>
        <button type="submit" className="btn">Register</button>
        <div className="switch-auth">
          Already have an account?{' '}
          <a onClick={onSwitchToLogin}>Login</a>
        </div>
        <div className="auth-copyright">
          <p>© 2025 Hemanth Anamala</p>
          <p>All Rights Reserved</p>
        </div>
      </form>
    </div>
  );
};

// File Viewer Modal
const FileViewerModal = ({ file, onClose }) => {
  if (!file) return null;

  const isImage = file.type && file.type.startsWith('image/');
  const isVideo = file.type && file.type.startsWith('video/');
  const isPDF = file.type && file.type.includes('pdf');

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
  };

  return (
    <div className="modal active" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <span className="modal-close" onClick={onClose}>&times;</span>
        <div className="viewer-content">
          {isImage && (
            <img
              src={`data:${file.type};base64,${file.fileData}`}
              alt={file.filename}
              className="modal-viewer"
            />
          )}
          {isVideo && (
            <video className="modal-viewer" controls>
              <source src={`data:${file.type};base64,${file.fileData}`} type={file.type} />
            </video>
          )}
          {isPDF && (
            <iframe
              src={`data:${file.type};base64,${file.fileData}`}
              className="modal-viewer"
              style={{ width: '80vw', height: '80vh' }}
              title={file.filename}
            />
          )}
        </div>
        <div className="modal-info">
          <div className="modal-filename">{file.filename}</div>
          <div className="modal-meta">
            {formatFileSize(file.size)} • {new Date(file.uploadDate).toLocaleString()}
          </div>
        </div>
      </div>
    </div>
  );
};

// Main App Component
const CloudStorageApp = () => {
  const { authToken, currentUser, logout } = useAuth();
  const [showRegister, setShowRegister] = useState(false);
  const [files, setFiles] = useState([]);
  const [stats, setStats] = useState({ totalFiles: 0, totalSize: 0 });
  const [searchQuery, setSearchQuery] = useState('');
  const [currentFilter, setCurrentFilter] = useState('all');
  const [statusMessage, setStatusMessage] = useState(null);
  const [viewingFile, setViewingFile] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (authToken) {
      loadFiles();
      loadStats();
    }
  }, [authToken]);

  useEffect(() => {
    const timer = setTimeout(() => {
      if (searchQuery) {
        searchFiles(searchQuery);
      } else if (authToken) {
        loadFiles();
      }
    }, 300);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  const showStatus = (message, type) => {
    setStatusMessage({ message, type });
    setTimeout(() => setStatusMessage(null), 4000);
  };

  const loadFiles = async () => {
    if (!authToken) return;
    setLoading(true);
    try {
      const response = await fetch(`${API_URL}/files`, {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      const data = await response.json();
      if (data.success) {
        setFiles(data.files);
      }
    } catch (error) {
      showStatus('Error loading files: ' + error.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  const loadStats = async () => {
    if (!authToken) return;
    try {
      const response = await fetch(`${API_URL}/stats`, {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      const data = await response.json();
      if (data.success) {
        setStats(data.stats);
      }
    } catch (error) {
      console.error('Stats error:', error);
    }
  };

  const searchFiles = async (query) => {
    if (!authToken) return;
    try {
      const response = await fetch(`${API_URL}/files/search/${encodeURIComponent(query)}`, {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      const data = await response.json();
      if (data.success) {
        setFiles(data.files);
      }
    } catch (error) {
      console.error('Search error:', error);
    }
  };

  const handleFileUpload = async (file) => {
    showStatus('Uploading file...', 'info');
    
    const reader = new FileReader();
    reader.onload = async (e) => {
      const base64Data = e.target.result.split(',')[1];
      
      try {
        const response = await fetch(`${API_URL}/files/upload`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${authToken}`
          },
          body: JSON.stringify({
            filename: file.name,
            fileData: base64Data,
            size: file.size,
            type: file.type
          })
        });

        const result = await response.json();
        
        if (response.ok && result.success) {
          showStatus(`✅ ${file.name} uploaded successfully!`, 'success');
          loadFiles();
          loadStats();
        } else {
          showStatus('Upload failed: ' + (result.error || 'Unknown error'), 'error');
        }
      } catch (error) {
        showStatus('Upload failed: ' + error.message, 'error');
      }
    };
    reader.readAsDataURL(file);
  };

  const handleFileDelete = async (fileId) => {
    if (!window.confirm('Are you sure you want to delete this file?')) return;

    try {
      const response = await fetch(`${API_URL}/files/${fileId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${authToken}` }
      });

      const data = await response.json();
      
      if (data.success) {
        showStatus('✅ File deleted successfully!', 'success');
        loadFiles();
        loadStats();
      } else {
        showStatus('Delete failed', 'error');
      }
    } catch (error) {
      showStatus('Delete failed: ' + error.message, 'error');
    }
  };

  const handleFileDownload = async (fileId, filename) => {
    try {
      const response = await fetch(`${API_URL}/files/${fileId}`, {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      const data = await response.json();
      
      if (data.success && data.file) {
        const link = document.createElement('a');
        link.href = 'data:application/octet-stream;base64,' + data.file.fileData;
        link.download = filename;
        link.click();
        showStatus(`✅ ${filename} downloaded!`, 'success');
      }
    } catch (error) {
      showStatus('Download failed: ' + error.message, 'error');
    }
  };

  const handleFileView = async (fileId) => {
    try {
      const response = await fetch(`${API_URL}/files/${fileId}`, {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      const data = await response.json();
      
      if (data.success && data.file) {
        setViewingFile(data.file);
      }
    } catch (error) {
      showStatus('Failed to load file: ' + error.message, 'error');
    }
  };

  const getFileIcon = (type) => {
    if (type?.startsWith('image/')) return '🖼️';
    if (type?.startsWith('video/')) return '🎥';
    if (type?.includes('pdf')) return '📄';
    if (type?.includes('word') || type?.includes('document')) return '📝';
    if (type?.includes('audio')) return '🎵';
    if (type?.includes('zip') || type?.includes('rar')) return '📦';
    if (type?.includes('excel')) return '📊';
    return '📁';
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
  };

  const canPreview = (type) => {
    return type?.startsWith('image/') || type?.startsWith('video/') || type?.includes('pdf');
  };

  const filterFilesByCategory = (files, category) => {
    switch (category) {
      case 'images':
        return files.filter(f => f.type?.startsWith('image/'));
      case 'videos':
        return files.filter(f => f.type?.startsWith('video/'));
      case 'documents':
        return files.filter(f => f.type?.includes('pdf') || f.type?.includes('document') || f.type?.includes('word'));
      case 'others':
        return files.filter(f => !f.type?.startsWith('image/') && !f.type?.startsWith('video/') && !f.type?.includes('pdf') && !f.type?.includes('document'));
      default:
        return files;
    }
  };

  const filteredFiles = filterFilesByCategory(files, currentFilter);

  if (!authToken) {
    return (
      <div className="auth-container">
        {showRegister ? (
          <RegisterForm onSwitchToLogin={() => setShowRegister(false)} />
        ) : (
          <LoginForm onSwitchToRegister={() => setShowRegister(true)} />
        )}
      </div>
    );
  }

  return (
    <div className="app-container">
      <header className="header">
        <h1>☁️ Cloud File Storage</h1>
        <div className="user-info">
          <span>Welcome, {currentUser?.name}!</span>
          <button className="btn btn-logout" onClick={logout}>
            <LogOut size={16} /> Logout
          </button>
        </div>
      </header>

      {statusMessage && (
        <div className={`status-message status-${statusMessage.type}`}>
          {statusMessage.message}
        </div>
      )}

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-value">{stats.totalFiles}</div>
          <div className="stat-label">Total Files</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{formatFileSize(stats.totalSize)}</div>
          <div className="stat-label">Total Storage</div>
        </div>
      </div>

      <div className="search-section">
        <div className="search-input-wrapper">
          <Search size={20} />
          <input
            type="text"
            className="search-input"
            placeholder="🔍 Search files by name..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
      </div>

      <div className="filter-tabs">
        {['all', 'images', 'videos', 'documents', 'others'].map(filter => (
          <button
            key={filter}
            className={`filter-tab ${currentFilter === filter ? 'active' : ''}`}
            onClick={() => setCurrentFilter(filter)}
          >
            {filter === 'all' && '📁 All Files'}
            {filter === 'images' && '🖼️ Images'}
            {filter === 'videos' && '🎥 Videos'}
            {filter === 'documents' && '📄 Documents'}
            {filter === 'others' && '📦 Others'}
          </button>
        ))}
      </div>

      <div className="upload-section">
        <h2>📤 Upload File</h2>
        <label className="upload-area">
          <input
            type="file"
            onChange={(e) => e.target.files[0] && handleFileUpload(e.target.files[0])}
            style={{ display: 'none' }}
          />
          <div className="upload-icon">📁</div>
          <h3>Click to Upload</h3>
          <p>Support for all file types</p>
        </label>
      </div>

      <div className="file-list-section">
        <h2>📂 My Files</h2>
        {loading ? (
          <div className="loading">Loading files...</div>
        ) : filteredFiles.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">🔭</div>
            <p>No files found</p>
          </div>
        ) : (
          <div className="file-list">
            {filteredFiles.map(file => (
              <div key={file._id} className="file-item">
                <div className="file-info">
                  {file.type?.startsWith('image/') ? (
                    <img
                      src={`data:${file.type};base64,${file.fileData}`}
                      className="file-thumbnail"
                      onClick={() => handleFileView(file._id)}
                      alt={file.filename}
                    />
                  ) : (
                    <div className="file-icon">{getFileIcon(file.type)}</div>
                  )}
                  <div className="file-details">
                    <div className="file-name">{file.filename}</div>
                    <div className="file-meta">
                      Size: {formatFileSize(file.size)} | 
                      Uploaded: {new Date(file.uploadDate).toLocaleString()}
                    </div>
                  </div>
                </div>
                <div className="file-actions">
                  {canPreview(file.type) && (
                    <button className="btn btn-small btn-info" onClick={() => handleFileView(file._id)}>
                      View
                    </button>
                  )}
                  <button className="btn btn-small btn-success" onClick={() => handleFileDownload(file._id, file.filename)}>
                    Download
                  </button>
                  <button className="btn btn-small btn-danger" onClick={() => handleFileDelete(file._id)}>
                    Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <footer className="footer">
        <p className="copyright">© 2025 Hemanth Anamala</p>
        <p className="developer">Developer & Creator</p>
        <p>Cloud File Storage System</p>
        <p className="tagline">All Rights Reserved</p>
      </footer>

      {viewingFile && <FileViewerModal file={viewingFile} onClose={() => setViewingFile(null)} />}
    </div>
  );
};

// App wrapper with AuthProvider
export default function App() {
  return (
    <AuthProvider>
      <CloudStorageApp />
    </AuthProvider>
  );
}

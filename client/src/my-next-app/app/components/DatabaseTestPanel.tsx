/**
 * Database Test Panel Component
 * Provides UI for testing database operations
 */

'use client';

import React, { useState } from 'react';

interface TestResult {
  success: boolean;
  message: string;
  data?: any;
}

export default function DatabaseTestPanel() {
  const [results, setResults] = useState<{ [key: string]: TestResult }>({});
  const [isLoading, setIsLoading] = useState(false);
  const [showPanel, setShowPanel] = useState(false);

  const runTest = async (testName: string, testFunction: () => Promise<any>) => {
    setIsLoading(true);
    try {
      const result = await testFunction();
      setResults(prev => ({
        ...prev,
        [testName]: {
          success: true,
          message: 'Test completed successfully',
          data: result
        }
      }));
    } catch (error) {
      setResults(prev => ({
        ...prev,
        [testName]: {
          success: false,
          message: error instanceof Error ? error.message : 'Unknown error'
        }
      }));
    }
    setIsLoading(false);
  };

  const testHealthCheck = async () => {
    const response = await fetch('/api/health');
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Health check failed');
    return data;
  };

  const testMigration = async () => {
    // Import and run migration
    const { runMigration } = await import('../../lib/migration');
    return await runMigration();
  };

  const testDatabaseOps = async () => {
    // Import and run database tests
    const { runAllTests } = await import('../../lib/test-database');
    return await runAllTests();
  };

  const testApiEndpoints = async () => {
    const tests = [];
    
    // Test each API endpoint
    const endpoints = [
      { name: 'architectures', url: '/api/architectures?user_id=sample_user_123&limit=5' },
      { name: 'attacks', url: '/api/attacks?user_id=sample_user_123&limit=5' },
      { name: 'healing', url: '/api/healing?user_id=sample_user_123&limit=5' }
    ];
    
    for (const endpoint of endpoints) {
      try {
        const response = await fetch(endpoint.url);
        const data = await response.json();
        tests.push({
          endpoint: endpoint.name,
          status: response.ok ? 'success' : 'failed',
          data: data
        });
      } catch (error) {
        tests.push({
          endpoint: endpoint.name,
          status: 'error',
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }
    
    return tests;
  };

  const clearResults = () => {
    setResults({});
  };

  if (!showPanel) {
    return (
      <div className="fixed bottom-4 right-4 z-50">
        <button
          onClick={() => setShowPanel(true)}
          className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg shadow-lg"
        >
          🧪 Database Tests
        </button>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-4xl max-h-[90vh] overflow-auto">
        <div className="p-6">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-2xl font-bold text-gray-800">🧪 Database Test Panel</h2>
            <button
              onClick={() => setShowPanel(false)}
              className="text-gray-500 hover:text-gray-700 text-xl"
            >
              ✕
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            <button
              onClick={() => runTest('health', testHealthCheck)}
              disabled={isLoading}
              className="bg-green-600 hover:bg-green-700 disabled:bg-gray-400 text-white px-4 py-3 rounded-lg"
            >
              🏥 Health Check
            </button>

            <button
              onClick={() => runTest('api', testApiEndpoints)}
              disabled={isLoading}
              className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white px-4 py-3 rounded-lg"
            >
              🌐 Test API Endpoints
            </button>

            <button
              onClick={() => runTest('database', testDatabaseOps)}
              disabled={isLoading}
              className="bg-purple-600 hover:bg-purple-700 disabled:bg-gray-400 text-white px-4 py-3 rounded-lg"
            >
              🗄️ Test Database CRUD
            </button>

            <button
              onClick={() => runTest('migration', testMigration)}
              disabled={isLoading}
              className="bg-orange-600 hover:bg-orange-700 disabled:bg-gray-400 text-white px-4 py-3 rounded-lg"
            >
              📦 Run Migration
            </button>
          </div>

          <div className="flex gap-4 mb-6">
            <button
              onClick={clearResults}
              className="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-lg"
            >
              🗑️ Clear Results
            </button>
            {isLoading && (
              <div className="flex items-center text-blue-600">
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600 mr-2"></div>
                Running test...
              </div>
            )}
          </div>

          <div className="space-y-4">
            {Object.entries(results).map(([testName, result]) => (
              <div
                key={testName}
                className={`p-4 rounded-lg border ${
                  result.success
                    ? 'bg-green-50 border-green-200'
                    : 'bg-red-50 border-red-200'
                }`}
              >
                <div className="flex items-center mb-2">
                  <span className={`mr-2 ${result.success ? 'text-green-600' : 'text-red-600'}`}>
                    {result.success ? '✅' : '❌'}
                  </span>
                  <h3 className="font-semibold text-gray-800 capitalize">{testName} Test</h3>
                </div>
                <p className={`text-sm ${result.success ? 'text-green-700' : 'text-red-700'}`}>
                  {result.message}
                </p>
                {result.data && (
                  <details className="mt-2">
                    <summary className="cursor-pointer text-sm text-gray-600 hover:text-gray-800">
                      View Details
                    </summary>
                    <pre className="mt-2 p-2 bg-gray-100 rounded text-xs overflow-auto max-h-40">
                      {JSON.stringify(result.data, null, 2)}
                    </pre>
                  </details>
                )}
              </div>
            ))}
          </div>

          {Object.keys(results).length === 0 && (
            <div className="text-center text-gray-500 py-8">
              Click a test button above to start testing the database functionality.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
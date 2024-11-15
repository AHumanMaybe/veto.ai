import { useState, useEffect, useRef } from 'react';
import './App.css';

function App() {
  const [anomalies, setAnomalies] = useState([]);
  const [isRunning, setIsRunning] = useState(false);
  const intervalRef = useRef(null);  // To store the interval ID

  // Function to fetch anomalies from the backend
  const fetchAnomalies = async () => {
    try {
      const response = await fetch('http://localhost:5000/start_detection_sse');
      const data = await response.json();
      console.log(data); // Log the response
  
      // Check if the data has the "action" key instead of an array
      if (data.action) {
        const currentTime = new Date().toLocaleString(); // Get the current time in a human-readable format
        setAnomalies(prevAnomalies => [
          ...prevAnomalies,
          { action: data.action, time: currentTime }
        ]); // Add the action and time as a new anomaly
      } else {
        console.error("Fetched data does not contain an 'action' key:", data);
      }
    } catch (error) {
      console.error("Error fetching anomalies:", error);
    }
  };

  // Function to start/stop the repeated fetch call
  const toggleDetection = () => {
    if (isRunning) {
      clearInterval(intervalRef.current);  // Stop the interval if already running
      setIsRunning(false);
    } else {
      intervalRef.current = setInterval(() => {
        fetchAnomalies();  // Call the fetch function every 5 seconds
      }, 5000); // 5 seconds interval
      setIsRunning(true);
    }
  };

  // Clean up on component unmount to avoid memory leaks
  useEffect(() => {
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);  // Clear interval when the component unmounts
      }
    };
  }, []);

  return (
    <div className="flex-col w-full">
      <div className="flex justify-center items-center w-full my-2">
        <img src="/vetoai.png" className="h-16 w-auto" alt="Veto.AI Logo" />
      </div>
      
      <h1 className="text-5xl font-bold mb-4"><span className='text-red-500'>Veto.AI</span> Anomaly Response Log</h1>

      {/* Button to start/stop anomaly detection */}
      <button
        onClick={toggleDetection}
        className="mb-4 px-4 py-2 bg-red-500 text-white rounded hover:bg-red-600"
      >
        {isRunning ? 'Stop Detection' : 'Start Detection'}
      </button>

      {/* Scrollable container */}
      <div className="flex w-full h-64 border-2 border-stone-600 rounded overflow-y-scroll p-2 justify-center">
        <ul className="flex-col w-5/6 rounded-lg list-none space-y-2">
          {anomalies.length > 0 ? (
            anomalies.map((anomaly, index) => (
              <li key={index} className="text-white border-b border-stone-600 hover:bg-stone-700 cursor-pointer">
                <strong>Action:</strong> {anomaly.action} 
                <br />
                <small className="text-gray-400">Detected at: {anomaly.time}</small>
              </li>
            ))
          ) : (
            <p>No anomalies detected.</p>
          )}
        </ul>
      </div>
    </div>
  );
}

export default App;

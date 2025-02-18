import React, { useState, useEffect } from 'react';
import { ScatterChart, Scatter, XAxis, YAxis, ZAxis, CartesianGrid, Tooltip, Legend } from 'recharts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import _ from 'lodash';

const NetworkTopologyVisualization = ({ data }) => {
  const [processedData, setProcessedData] = useState([]);
  const [selectedNode, setSelectedNode] = useState(null);

  useEffect(() => {
    if (!data || !data.nodes || !data.links) return;
    
    // Process nodes into a format suitable for visualization
    const processedNodes = processNetworkData(data);
    setProcessedData(processedNodes);
  }, [data]);

  // Process network data into a suitable format for visualization
  const processNetworkData = (networkData) => {
    const nodes = networkData.nodes.map((node, index) => {
      // Create a circular layout
      const angle = (2 * Math.PI * index) / networkData.nodes.length;
      const radius = 100;
      
      return {
        id: node.id,
        name: node.name,
        type: node.type,
        x: Math.cos(angle) * radius + 200, // Center at 200
        y: Math.sin(angle) * radius + 200, // Center at 200
        size: getNodeSize(node.type),
        color: getNodeColor(node.type)
      };
    });

    return nodes;
  };

  const getNodeSize = (type) => {
    const sizes = {
      'host': 100,
      'subdomain': 80,
      'service': 60,
      'gateway': 40
    };
    return sizes[type] || 60;
  };

  const getNodeColor = (type) => {
    const colors = {
      'host': '#ff4444',
      'subdomain': '#44ff44',
      'service': '#4444ff',
      'gateway': '#ffff44'
    };
    return colors[type] || '#999999';
  };

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      return (
        <div className="bg-white p-4 border rounded shadow">
          <p className="font-bold">{data.name}</p>
          <p className="text-sm">Type: {data.type}</p>
        </div>
      );
    }
    return null;
  };

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle>Network Topology Visualization</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="w-full h-96">
          <ScatterChart
            width={800}
            height={400}
            margin={{
              top: 20,
              right: 20,
              bottom: 20,
              left: 20,
            }}
          >
            <CartesianGrid />
            <XAxis type="number" dataKey="x" domain={[0, 400]} hide />
            <YAxis type="number" dataKey="y" domain={[0, 400]} hide />
            <ZAxis type="number" dataKey="size" range={[100, 1000]} />
            <Tooltip content={<CustomTooltip />} />
            <Legend />
            <Scatter
              name="Nodes"
              data={processedData}
              fill="#8884d8"
              shape="circle"
            />
          </ScatterChart>
        </div>
        
        {/* Node Types Legend */}
        <div className="mt-4 flex gap-4 justify-center">
          {['host', 'subdomain', 'service', 'gateway'].map(type => (
            <div key={type} className="flex items-center">
              <div 
                className="w-4 h-4 rounded-full mr-2"
                style={{ backgroundColor: getNodeColor(type) }}
              />
              <span className="capitalize">{type}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};

export default NetworkTopologyVisualization;
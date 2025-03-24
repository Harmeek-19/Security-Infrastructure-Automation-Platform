// NetworkTopologyVisualization.js

/**
 * Network Topology Visualization Component
 * Renders network mapping data using D3.js
 */
class NetworkTopologyVisualization {
  constructor(containerId) {
      this.containerId = containerId;
      this.width = 800;
      this.height = 600;
      this.nodeRadius = 15;
      this.simulation = null;
      this.svg = null;
      this.nodeElements = null;
      this.linkElements = null;
      this.textElements = null;
  }

  /**
   * Initialize the visualization with data
   * @param {Object} data - Network topology data with nodes and links
   */
  init(data) {
      try {
          // Ensure data is properly parsed if it's a string
          if (typeof data === 'string') {
              try {
                  data = JSON.parse(data);
              } catch (e) {
                  console.error("Error parsing network data:", e);
                  document.getElementById(this.containerId).innerHTML = 
                      `<div class="alert alert-danger">Error parsing network data: ${e.message}</div>`;
                  return;
              }
          }

          // Validate the data structure
          if (!data || !Array.isArray(data.nodes) || !Array.isArray(data.links)) {
              console.error("Invalid network data format:", data);
              document.getElementById(this.containerId).innerHTML = 
                  `<div class="alert alert-danger">Invalid network data format. Expected nodes and links arrays.</div>`;
              return;
          }

          // Create SVG container
          this.svg = d3.select(`#${this.containerId}`)
              .append("svg")
              .attr("width", this.width)
              .attr("height", this.height)
              .append("g")
              .attr("class", "network-container");

          // Add zoom functionality
          const zoom = d3.zoom()
              .scaleExtent([0.1, 4])
              .on("zoom", (event) => {
                  this.svg.attr("transform", event.transform);
              });

          d3.select(`#${this.containerId} svg`).call(zoom);

          // Create force simulation
          this.simulation = d3.forceSimulation()
              .force("link", d3.forceLink().id(d => d.id).distance(100))
              .force("charge", d3.forceManyBody().strength(-400))
              .force("center", d3.forceCenter(this.width / 2, this.height / 2))
              .force("collision", d3.forceCollide().radius(this.nodeRadius * 1.5));

          // Create links
          this.linkElements = this.svg.append("g")
              .attr("class", "links")
              .selectAll("line")
              .data(data.links)
              .enter()
              .append("line")
              .attr("stroke-width", 2)
              .attr("stroke", "#999");

          // Create node groups
          const nodeGroups = this.svg.append("g")
              .attr("class", "nodes")
              .selectAll("g")
              .data(data.nodes)
              .enter()
              .append("g")
              .call(d3.drag()
                  .on("start", this.dragStarted.bind(this))
                  .on("drag", this.dragged.bind(this))
                  .on("end", this.dragEnded.bind(this)));

          // Add circles to node groups
          this.nodeElements = nodeGroups.append("circle")
              .attr("r", this.nodeRadius)
              .attr("fill", d => this.getNodeColor(d.type))
              .attr("stroke", "#fff")
              .attr("stroke-width", 1.5);

          // Add tooltips
          nodeGroups.append("title")
              .text(d => `${d.id}\nType: ${d.type}\n${d.info || ''}`);

          // Add text labels
          this.textElements = nodeGroups.append("text")
              .text(d => this.getNodeLabel(d))
              .attr("font-size", 12)
              .attr("dx", 20)
              .attr("dy", 4)
              .attr("fill", "#333");

          // Update simulation
          this.simulation.nodes(data.nodes).on("tick", this.ticked.bind(this));
          this.simulation.force("link").links(data.links);

      } catch (error) {
          console.error("Error initializing network visualization:", error);
          document.getElementById(this.containerId).innerHTML = 
              `<div class="alert alert-danger">Error initializing network visualization: ${error.message}</div>`;
      }
  }

  /**
   * Handle simulation tick events
   */
  ticked() {
      this.linkElements
          .attr("x1", d => d.source.x)
          .attr("y1", d => d.source.y)
          .attr("x2", d => d.target.x)
          .attr("y2", d => d.target.y);

      this.nodeElements
          .attr("cx", d => d.x)
          .attr("cy", d => d.y);

      this.textElements
          .attr("x", d => d.x)
          .attr("y", d => d.y);
  }

  /**
   * Handle drag start
   * @param {Event} event - D3 drag event
   */
  dragStarted(event, d) {
      if (!event.active) this.simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
  }

  /**
   * Handle drag
   * @param {Event} event - D3 drag event
   */
  dragged(event, d) {
      d.fx = event.x;
      d.fy = event.y;
  }

  /**
   * Handle drag end
   * @param {Event} event - D3 drag event
   */
  dragEnded(event, d) {
      if (!event.active) this.simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
  }

  /**
   * Get color based on node type
   * @param {string} type - Node type
   * @returns {string} - Color code
   */
  getNodeColor(type) {
      const colorMap = {
          'host': '#4CAF50',     // Green
          'domain': '#2196F3',   // Blue
          'subdomain': '#03A9F4', // Light Blue
          'service': '#FF9800',  // Orange
          'port': '#9C27B0',     // Purple
          'vulnerability': '#F44336', // Red
          'gateway': '#795548'   // Brown
      };
      return colorMap[type] || '#777777';
  }

  /**
   * Get label text based on node data
   * @param {Object} node - Node data
   * @returns {string} - Label text
   */
  getNodeLabel(node) {
      if (node.type === 'port') {
          return `Port ${node.id.split('-').pop()}`;
      } else if (node.type === 'service') {
          return node.name || node.id;
      } else {
          // For domains, hosts, etc.
          const parts = node.id.split('.');
          return parts.length > 2 ? parts[0] : node.name || node.id;
      }
  }
}